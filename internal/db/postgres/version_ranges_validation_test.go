package postgres

import (
	"encoding/json"
	"testing"
)

// storedVersionRangeCase is shared by the Go validator unit test and the
// Docker-backed parity test against packmon_jsonb_version_ranges_valid, so the
// store pre-check and the database CHECK constraint cannot drift apart.
type storedVersionRangeCase struct {
	name  string
	raw   string
	valid bool
	// goOnly marks inputs only the Go check rejects: Go trims Unicode
	// whitespace, the SQL function trims ASCII whitespace. The SQL check may be
	// more lenient than Go, never stricter, so a value Go accepted always
	// stores.
	goOnly bool
}

var storedVersionRangeCases = []storedVersionRangeCase{
	{name: "empty array", raw: `[]`, valid: true},
	{name: "osv single-key events", raw: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`, valid: true},
	{name: "ghsa blank sibling keys", raw: `[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"","last_affected":""}]}]`, valid: true},
	{name: "null sibling key", raw: `[{"events":[{"introduced":"0","fixed":null}]}]`, valid: true},
	{name: "last_affected only", raw: `[{"events":[{"last_affected":"3.1"}]}]`, valid: true},
	{name: "limit only", raw: `[{"events":[{"limit":"*"}]}]`, valid: true},
	{name: "extra range and event keys", raw: `[{"type":"GIT","repo":"https://example.invalid","events":[{"introduced":"abc","note":1}],"database_specific":{}}]`, valid: true},
	{name: "range without events", raw: `[{}]`},
	{name: "range with null events", raw: `[{"events":null}]`},
	{name: "range with empty events", raw: `[{"events":[]}]`},
	{name: "range with object events", raw: `[{"events":{}}]`},
	{name: "range with string events", raw: `[{"events":"0"}]`},
	{name: "null range", raw: `[null]`},
	{name: "string range", raw: `["0"]`},
	{name: "array range", raw: `[[]]`},
	{name: "null event", raw: `[{"events":[null]}]`},
	{name: "string event", raw: `[{"events":["0"]}]`},
	{name: "empty event", raw: `[{"events":[{}]}]`},
	{name: "unknown-key-only event", raw: `[{"events":[{"version":"1.0"}]}]`},
	{name: "null boundary", raw: `[{"events":[{"introduced":null}]}]`},
	{name: "numeric boundary", raw: `[{"events":[{"introduced":1}]}]`},
	{name: "boolean boundary", raw: `[{"events":[{"fixed":true}]}]`},
	{name: "object boundary", raw: `[{"events":[{"limit":{}}]}]`},
	{name: "empty boundary", raw: `[{"events":[{"introduced":""}]}]`},
	{name: "ascii blank boundary", raw: `[{"events":[{"introduced":" \t\n"}]}]`},
	{name: "numeric sibling of a valid boundary", raw: `[{"events":[{"introduced":"0","fixed":5}]}]`},
	{name: "case-variant key", raw: `[{"events":[{"Introduced":"0"}]}]`},
	{name: "case-variant events key", raw: `[{"Events":[{"introduced":"0"}]}]`},
	{name: "valid range then invalid range", raw: `[{"events":[{"introduced":"0"}]},{}]`},
	{name: "valid event then invalid event", raw: `[{"events":[{"introduced":"0"},{"fixed":""}]}]`},
	{name: "unicode blank boundary", raw: "[{\"events\":[{\"introduced\":\" \"}]}]", goOnly: true},
	// The range matcher reads type as a string; only Go enforces that.
	{name: "numeric type", raw: `[{"type":1,"events":[{"introduced":"0"}]}]`, goOnly: true},
}

func TestValidateStoredVersionRangesJSONCases(t *testing.T) {
	t.Parallel()

	for _, tc := range storedVersionRangeCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateStoredVersionRangesJSON("GHSA-case", "version_ranges", json.RawMessage(tc.raw), false)
			if tc.valid && err != nil {
				t.Fatalf("validateStoredVersionRangesJSON(%s) error = %v, want valid", tc.raw, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("validateStoredVersionRangesJSON(%s) = nil, want rejection", tc.raw)
			}
		})
	}
}
