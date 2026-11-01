package version

import "testing"

// TestCheckRangesShape pins the shared stored-range rule and the location it
// reports. The handler and the PostgreSQL store both format their messages
// from Path and Reason; the Docker parity test in internal/db/postgres checks
// the same rule against the database CHECK function.
func TestCheckRangesShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		wantPath   string
		wantReason string // empty: valid
	}{
		{name: "empty array", raw: `[]`},
		{name: "osv single-key events", raw: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`},
		{name: "ghsa blank sibling keys", raw: `[{"events":[{"introduced":"0","fixed":"","last_affected":""}]}]`},
		{name: "null sibling key", raw: `[{"events":[{"introduced":"0","fixed":null}]}]`},
		{name: "last_affected only", raw: `[{"events":[{"last_affected":"3.1"}]}]`},
		{name: "limit only", raw: `[{"events":[{"limit":"*"}]}]`},
		{name: "extra keys", raw: `[{"type":"GIT","repo":"r","events":[{"introduced":"abc","note":1}],"database_specific":{}}]`},
		{name: "not an array", raw: `{"introduced":"0"}`, wantReason: "must be an array of range objects"},
		{name: "malformed JSON", raw: `[{`, wantReason: "must be an array of range objects"},
		{name: "null range", raw: `[null]`, wantPath: "[0]", wantReason: "must be a range object"},
		{name: "string range", raw: `["0"]`, wantPath: "[0]", wantReason: "must be a range object"},
		{name: "range without events", raw: `[{}]`, wantPath: "[0].events", wantReason: "must not be empty"},
		{name: "null events", raw: `[{"events":null}]`, wantPath: "[0].events", wantReason: "must not be empty"},
		{name: "empty events", raw: `[{"events":[]}]`, wantPath: "[0].events", wantReason: "must not be empty"},
		{name: "object events", raw: `[{"events":{}}]`, wantPath: "[0].events", wantReason: "must be an array of event objects"},
		{name: "case-variant events key", raw: `[{"Events":[{"introduced":"0"}]}]`, wantPath: "[0].events", wantReason: "must not be empty"},
		{name: "null event", raw: `[{"events":[null]}]`, wantPath: "[0].events[0]", wantReason: "must be an event object"},
		{name: "empty event", raw: `[{"events":[{}]}]`, wantPath: "[0].events[0]", wantReason: "must set introduced, fixed, last_affected, or limit"},
		{name: "null boundary", raw: `[{"events":[{"introduced":null}]}]`, wantPath: "[0].events[0]", wantReason: "must set introduced, fixed, last_affected, or limit"},
		{name: "blank boundary", raw: `[{"events":[{"introduced":" \t"}]}]`, wantPath: "[0].events[0]", wantReason: "must set introduced, fixed, last_affected, or limit"},
		{name: "unicode blank boundary", raw: "[{\"events\":[{\"introduced\":\" \"}]}]", wantPath: "[0].events[0]", wantReason: "must set introduced, fixed, last_affected, or limit"},
		{name: "case-variant boundary key", raw: `[{"events":[{"Introduced":"0"}]}]`, wantPath: "[0].events[0]", wantReason: "must set introduced, fixed, last_affected, or limit"},
		{name: "numeric boundary", raw: `[{"events":[{"introduced":1}]}]`, wantPath: "[0].events[0].introduced", wantReason: "must be a string"},
		{name: "numeric sibling", raw: `[{"events":[{"introduced":"0","fixed":5}]}]`, wantPath: "[0].events[0].fixed", wantReason: "must be a string"},
		{name: "second range invalid", raw: `[{"events":[{"introduced":"0"}]},{}]`, wantPath: "[1].events", wantReason: "must not be empty"},
		{name: "second event invalid", raw: `[{"events":[{"introduced":"0"},{"fixed":""}]}]`, wantPath: "[0].events[1]", wantReason: "must set introduced, fixed, last_affected, or limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := CheckRangesShape([]byte(tt.raw))
			if tt.wantReason == "" {
				if got != nil {
					t.Fatalf("CheckRangesShape(%s) = %v, want valid", tt.raw, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("CheckRangesShape(%s) = nil, want %q at %q", tt.raw, tt.wantReason, tt.wantPath)
			}
			if got.Path != tt.wantPath || got.Reason != tt.wantReason {
				t.Fatalf("CheckRangesShape(%s) = {%q %q}, want {%q %q}", tt.raw, got.Path, got.Reason, tt.wantPath, tt.wantReason)
			}
		})
	}
}

func TestRangeShapeErrorMessage(t *testing.T) {
	t.Parallel()

	if got := (&RangeShapeError{Reason: "must be an array of range objects"}).Error(); got != "must be an array of range objects" {
		t.Fatalf("Error() without path = %q", got)
	}
	if got := (&RangeShapeError{Path: "[0].events", Reason: "must not be empty"}).Error(); got != "[0].events must not be empty" {
		t.Fatalf("Error() with path = %q", got)
	}
}
