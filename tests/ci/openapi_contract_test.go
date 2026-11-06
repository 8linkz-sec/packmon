package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	apiv1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
	"github.com/8linkz-sec/packmon/internal/synccontract"
	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/datamodel"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

type feedImportContractCase struct {
	feed               string
	path               string
	schemaName         string
	operationID        string
	deprecated         bool
	statusOnlyAccepted bool
	body               string
	wrongBody          string
}

func feedImportContractCases() []feedImportContractCase {
	const (
		vulnerabilityBody = `{"vulnerabilities":[{"id":"OSV-selector","severity":"HIGH"}]}`
		maliciousBody     = `{"malicious":[{"id":"MAL-selector","ecosystem":"npm","name":"bad-package","severity":"HIGH"}]}`
		vulnCheckBody     = `{"entries":[{"cve_id":"CVE-2026-2001","exploit_exists":true}]}`
		cisaKEVBody       = `{"cve_ids":["CVE-2026-2002"]}`
		epssBody          = `{"entries":[{"cve_id":"CVE-2026-2003","score":0.5,"percentile":0.75}]}`
	)
	return []feedImportContractCase{
		{feed: "osv", path: "/api/v1/feeds/osv/import", schemaName: "VulnerabilityImportRequest", operationID: "importOSVFeed", statusOnlyAccepted: true, body: vulnerabilityBody, wrongBody: maliciousBody},
		{feed: "ghsa", path: "/api/v1/feeds/ghsa/import", schemaName: "VulnerabilityImportRequest", operationID: "importGHSAFeed", statusOnlyAccepted: true, body: vulnerabilityBody, wrongBody: maliciousBody},
		{feed: "openssf", path: "/api/v1/feeds/openssf/import", schemaName: "MaliciousImportRequest", operationID: "importOpenSSFFeed", statusOnlyAccepted: true, body: maliciousBody, wrongBody: vulnerabilityBody},
		{feed: "malicious", path: "/api/v1/feeds/malicious/import", schemaName: "MaliciousImportRequest", operationID: "importMaliciousFeed", deprecated: true, statusOnlyAccepted: true, body: maliciousBody, wrongBody: vulnerabilityBody},
		{feed: "socket", path: "/api/v1/feeds/socket/import", schemaName: "MaliciousImportRequest", operationID: "importSocketFeed", statusOnlyAccepted: true, body: maliciousBody, wrongBody: vulnerabilityBody},
		{feed: "vulncheck", path: "/api/v1/feeds/vulncheck/import", schemaName: "VulnCheckImportRequest", operationID: "importVulnCheckFeed", statusOnlyAccepted: true, body: vulnCheckBody, wrongBody: maliciousBody},
		{feed: "cisakev", path: "/api/v1/feeds/cisakev/import", schemaName: "CISAKEVImportRequest", operationID: "importCISAKEVFeed", statusOnlyAccepted: true, body: cisaKEVBody, wrongBody: vulnCheckBody},
		{feed: "epss", path: "/api/v1/feeds/epss/import", schemaName: "EPSSImportRequest", operationID: "importEPSSFeed", body: epssBody, wrongBody: vulnCheckBody},
	}
}

func openAPIJSONPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func TestOpenAPIIncludesCanonicalScanAndSyncFields(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	syncOperation := requireMap(t, requireMap(t, paths, "/api/v1/sync"), "get")
	for _, name := range []string{"since_xid", "snapshot_xid"} {
		parameter := requireOperationParameter(t, syncOperation, name, "query")
		schema := requireMap(t, parameter, "schema")
		if got := schema["type"]; got != "integer" {
			t.Fatalf("/api/v1/sync parameter %s type = %#v, want integer", name, got)
		}
		if got := requireInt(t, schema, "minimum"); got != 0 {
			t.Fatalf("/api/v1/sync parameter %s minimum = %d, want 0", name, got)
		}
		if got := requireInt(t, schema, "maximum"); got != 9223372036854775807 {
			t.Fatalf("/api/v1/sync parameter %s maximum = %d, want signed bigint max", name, got)
		}
	}

	importOperation := requireMap(t, requireMap(t, paths, "/api/v1/feeds/{feed}/import"), "post")
	feedParameter := requireOperationParameter(t, importOperation, "feed", "path")
	feedSchema := requireMap(t, feedParameter, "schema")
	feedEnums := requireStringEnum(t, feedSchema, "feed import path parameter")
	wantFeedEnums := apiv1.FeedImportPathFeedNames()
	if len(feedEnums) != len(wantFeedEnums) {
		t.Fatalf("feed import path enum length = %d (%v), want %d API capabilities", len(feedEnums), enumKeys(feedEnums), len(wantFeedEnums))
	}
	for _, want := range wantFeedEnums {
		if _, ok := feedEnums[want]; !ok {
			t.Fatalf("feed import path enum missing %q; got %v", want, enumKeys(feedEnums))
		}
	}
	if len(feedImportContractCases()) != len(wantFeedEnums) {
		t.Fatalf("concrete feed import operation count = %d, want %d API capabilities", len(feedImportContractCases()), len(wantFeedEnums))
	}
	for _, tt := range feedImportContractCases() {
		if _, ok := feedEnums[tt.feed]; !ok {
			t.Fatalf("concrete feed import operation %s is not present in the compatibility selector enum", tt.path)
		}
		if _, ok := paths[tt.path]; !ok {
			t.Fatalf("OpenAPI paths missing concrete feed import operation %s", tt.path)
		}
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	scanResultProperties := requireMap(t, requireMap(t, schemas, "ScanResult"), "properties")
	parseErrors := requireMap(t, scanResultProperties, "parse_errors")
	if got := parseErrors["type"]; got != "array" {
		t.Fatalf("ScanResult.parse_errors type = %#v, want array", got)
	}
	parseErrorItems := requireMap(t, parseErrors, "items")
	if got := parseErrorItems["type"]; got != "string" {
		t.Fatalf("ScanResult.parse_errors item type = %#v, want string", got)
	}
	findingsTruncated := requireMap(t, scanResultProperties, "findings_truncated")
	if got := findingsTruncated["type"]; got != "boolean" {
		t.Fatalf("ScanResult.findings_truncated type = %#v, want boolean", got)
	}

	findingProperties := requireMap(t, requireMap(t, schemas, "Finding"), "properties")
	resources := requireMap(t, findingProperties, "resources")
	if got := resources["type"]; got != "array" {
		t.Fatalf("Finding.resources type = %#v, want array", got)
	}
	resourceItems := requireMap(t, resources, "items")
	if got := resourceItems["$ref"]; got != "#/components/schemas/ResourceLink" {
		t.Fatalf("Finding.resources item ref = %#v, want ResourceLink", got)
	}
	resourceLink := requireMap(t, schemas, "ResourceLink")
	requireRequiredFields(t, resourceLink, "ResourceLink", "label", "url")

	syncResponseProperties := requireMap(t, requireMap(t, schemas, "SyncResponse"), "properties")
	syncedXID := requireMap(t, syncResponseProperties, "synced_xid")
	if got := syncedXID["type"]; got != "integer" {
		t.Fatalf("SyncResponse.synced_xid type = %#v, want integer", got)
	}
	feedStatus := requireMap(t, syncResponseProperties, "feed_status")
	if got := feedStatus["type"]; got != "string" {
		t.Fatalf("SyncResponse.feed_status type = %#v, want string", got)
	}
	syncFeedStatusEnums := requireStringEnum(t, feedStatus, "SyncResponse.feed_status")
	for _, want := range domain.ScanFeedStatusValues() {
		if _, ok := syncFeedStatusEnums[string(want)]; !ok {
			t.Errorf("SyncResponse.feed_status enum missing %q; got %v", want, enumKeys(syncFeedStatusEnums))
		}
	}
	feedVersions := requireMap(t, syncResponseProperties, "feed_versions")
	if got := feedVersions["type"]; got != "object" {
		t.Fatalf("SyncResponse.feed_versions type = %#v, want object", got)
	}
	hasMore := requireMap(t, syncResponseProperties, "has_more")
	if got := hasMore["type"]; got != "boolean" {
		t.Fatalf("SyncResponse.has_more type = %#v, want boolean", got)
	}
	if got := requireBool(t, hasMore, "deprecated"); !got {
		t.Fatalf("SyncResponse.has_more deprecated = %t, want true", got)
	}
	hasMoreDescription, _ := hasMore["description"].(string)
	for _, want := range []string{"API v1", "truncated", "next_cursor", "future major API version"} {
		if !strings.Contains(hasMoreDescription, want) {
			t.Fatalf("SyncResponse.has_more description missing %q versioning guidance: %q", want, hasMoreDescription)
		}
	}
	nextCursor := requireMap(t, syncResponseProperties, "next_cursor")
	if got := nextCursor["$ref"]; got != "#/components/schemas/SyncCursor" {
		t.Fatalf("SyncResponse.next_cursor ref = %#v, want SyncCursor", got)
	}
	reputationDisabled := requireMap(t, syncResponseProperties, "reputation_disabled")
	if got := reputationDisabled["type"]; got != "boolean" {
		t.Fatalf("SyncResponse.reputation_disabled type = %#v, want boolean", got)
	}
	reputationDisabledDescription, _ := reputationDisabled["description"].(string)
	for _, want := range []string{"ReversingLabs", "self", "drop", "omitted"} {
		if !strings.Contains(reputationDisabledDescription, want) {
			t.Fatalf("SyncResponse.reputation_disabled description missing %q: %q", want, reputationDisabledDescription)
		}
	}
	if fieldTag, ok := reflect.TypeOf(synccontract.Response{}).FieldByName("ReputationDisabled"); !ok || fieldTag.Tag.Get("json") != "reputation_disabled,omitempty" {
		t.Fatalf("synccontract.Response.ReputationDisabled json tag = %q (found %v), want reputation_disabled,omitempty", fieldTag.Tag.Get("json"), ok)
	}
	affectedComplete := requireMap(t, syncResponseProperties, "vulnerability_affected_complete")
	if got := affectedComplete["type"]; got != "boolean" {
		t.Fatalf("SyncResponse.vulnerability_affected_complete type = %#v, want boolean", got)
	}
	affectedCompleteDescription, _ := affectedComplete["description"].(string)
	for _, want := range []string{"since window", "this page", "every page of a multi-page delta", "whole advisories", "all of its current affected", "legacy", "byte budget omit the", "compatible"} {
		if !strings.Contains(affectedCompleteDescription, want) {
			t.Fatalf("SyncResponse.vulnerability_affected_complete description missing %q: %q", want, affectedCompleteDescription)
		}
	}
	for _, stale := range []string{"single page (not truncated", "planned follow-up"} {
		if strings.Contains(affectedCompleteDescription, stale) {
			t.Fatalf("SyncResponse.vulnerability_affected_complete description keeps the single-page-only wording %q: %q", stale, affectedCompleteDescription)
		}
	}
	if fieldTag, ok := reflect.TypeOf(synccontract.Response{}).FieldByName("VulnerabilityAffectedComplete"); !ok || fieldTag.Tag.Get("json") != "vulnerability_affected_complete,omitempty" {
		t.Fatalf("synccontract.Response.VulnerabilityAffectedComplete json tag = %q (found %v), want vulnerability_affected_complete,omitempty", fieldTag.Tag.Get("json"), ok)
	}
	withoutAffected := requireMap(t, syncResponseProperties, "vulnerabilities_without_affected")
	if got := withoutAffected["type"]; got != "array" {
		t.Fatalf("SyncResponse.vulnerabilities_without_affected type = %#v, want array", got)
	}
	if got := requireMap(t, withoutAffected, "items")["type"]; got != "string" {
		t.Fatalf("SyncResponse.vulnerabilities_without_affected items type = %#v, want string", got)
	}
	withoutAffectedDescription, _ := withoutAffected["description"].(string)
	for _, want := range []string{"vulnerability_affected_complete", "no affected package left", "requested ecosystems", "not package rows", "other ecosystems stay", "win over the list", "limit", "omitted", "older clients ignore"} {
		if !strings.Contains(withoutAffectedDescription, want) {
			t.Fatalf("SyncResponse.vulnerabilities_without_affected description missing %q: %q", want, withoutAffectedDescription)
		}
	}
	if fieldTag, ok := reflect.TypeOf(synccontract.Response{}).FieldByName("VulnerabilitiesWithoutAffected"); !ok || fieldTag.Tag.Get("json") != "vulnerabilities_without_affected,omitempty" {
		t.Fatalf("synccontract.Response.VulnerabilitiesWithoutAffected json tag = %q (found %v), want vulnerabilities_without_affected,omitempty", fieldTag.Tag.Get("json"), ok)
	}

	limit := requireOperationParameter(t, syncOperation, "limit", "query")
	limitSchema := requireMap(t, limit, "schema")
	if got := requireInt(t, limitSchema, "default"); got != synccontract.DefaultLimit {
		t.Fatalf("/api/v1/sync limit default = %d, want %d", got, synccontract.DefaultLimit)
	}
	if got := requireInt(t, limitSchema, "maximum"); got != synccontract.MaxLimit {
		t.Fatalf("/api/v1/sync limit maximum = %d, want %d", got, synccontract.MaxLimit)
	}
	limitDescription, _ := limit["description"].(string)
	for _, want := range []string{"whole advisories", "more affected rows than the limit", "byte budget", "32 MiB", "split over several pages", "omit vulnerability_affected_complete"} {
		if !strings.Contains(limitDescription, want) {
			t.Fatalf("/api/v1/sync limit description missing %q: %q", want, limitDescription)
		}
	}
	vulnerabilitiesCursorParameter := requireOperationParameter(t, syncOperation, "vulnerabilities_cursor", "query")
	vulnerabilitiesCursorDescription, _ := vulnerabilitiesCursorParameter["description"].(string)
	for _, want := range []string{"advisory cursor", "advisory row cursor", "page byte budget", "since", "legacy row cursor"} {
		if !strings.Contains(vulnerabilitiesCursorDescription, want) {
			t.Fatalf("/api/v1/sync vulnerabilities_cursor description missing %q: %q", want, vulnerabilitiesCursorDescription)
		}
	}
	for _, name := range []string{"offset", "vulnerabilities_offset", "malicious_offset", "reputation_offset", "lifecycle_offset"} {
		parameter := requireOperationParameter(t, syncOperation, name, "query")
		if got := requireBool(t, parameter, "deprecated"); !got {
			t.Fatalf("/api/v1/sync %s deprecated = %t, want true", name, got)
		}
		schema := requireMap(t, parameter, "schema")
		if got := requireInt(t, schema, "maximum"); got != 10000 {
			t.Fatalf("/api/v1/sync %s maximum = %d, want 10000", name, got)
		}
	}

	syncCursorProperties := requireMap(t, requireMap(t, schemas, "SyncCursor"), "properties")
	for _, name := range []string{"vulnerabilities", "malicious", "reputation", "lifecycle"} {
		property := requireMap(t, syncCursorProperties, name)
		if got := requireBool(t, property, "deprecated"); !got {
			t.Fatalf("SyncCursor.%s deprecated = %t, want true", name, got)
		}
	}
	vulnerabilitiesCursor := requireMap(t, syncCursorProperties, "vulnerabilities_cursor")
	if got := vulnerabilitiesCursor["type"]; got != "string" {
		t.Fatalf("SyncCursor.vulnerabilities_cursor type = %#v, want string", got)
	}
	reputationDone := requireMap(t, syncCursorProperties, "reputation_done")
	if got := reputationDone["type"]; got != "boolean" {
		t.Fatalf("SyncCursor.reputation_done type = %#v, want boolean", got)
	}

	syncVulnerabilityProperties := requireMap(t, requireMap(t, schemas, "SyncVulnerability"), "properties")
	versionsAffected := requireMap(t, syncVulnerabilityProperties, "versions_affected")
	if got := versionsAffected["type"]; got != "string" {
		t.Fatalf("SyncVulnerability.versions_affected type = %#v, want string", got)
	}
	vulnerabilitySource := requireMap(t, syncVulnerabilityProperties, "source")
	if got := vulnerabilitySource["type"]; got != "string" {
		t.Fatalf("SyncVulnerability.source type = %#v, want string", got)
	}
	epssPercentile := requireMap(t, syncVulnerabilityProperties, "epss_percentile")
	if got := epssPercentile["type"]; !reflect.DeepEqual(got, []any{"number", "null"}) {
		t.Fatalf("SyncVulnerability.epss_percentile type = %#v, want [number null]", got)
	}
	syncMaliciousProperties := requireMap(t, requireMap(t, schemas, "SyncMalicious"), "properties")
	referenceURLs := requireMap(t, syncMaliciousProperties, "reference_urls")
	if got := referenceURLs["type"]; got != "string" {
		t.Fatalf("SyncMalicious.reference_urls type = %#v, want string", got)
	}
	maliciousSource := requireMap(t, syncMaliciousProperties, "source")
	if got := maliciousSource["type"]; got != "string" {
		t.Fatalf("SyncMalicious.source type = %#v, want string", got)
	}
	syncLifecycleProperties := requireMap(t, requireMap(t, schemas, "SyncLifecycle"), "properties")
	for _, name := range []string{"release_date", "lts_from", "eoas_from", "eol_from", "discontinued_from", "eoes_from"} {
		property := requireMap(t, syncLifecycleProperties, name)
		if got := property["type"]; !reflect.DeepEqual(got, []any{"string", "null"}) {
			t.Fatalf("SyncLifecycle.%s type = %#v, want [string null]", name, got)
		}
		if got := property["format"]; got != "date" {
			t.Fatalf("SyncLifecycle.%s format = %#v, want date", name, got)
		}
	}

	feedStatusProperties := requireMap(t, requireMap(t, schemas, "FeedStatus"), "properties")
	status := requireMap(t, feedStatusProperties, "status")
	statusEnums := requireStringEnum(t, status, "FeedStatus.status")
	for _, want := range []string{"healthy", "warning", "error", "disabled", "pending", "configured"} {
		if _, ok := statusEnums[want]; !ok {
			t.Fatalf("FeedStatus.status enum missing %q; got %v", want, enumKeys(statusEnums))
		}
	}
	feedStatusResponseProperties := requireMap(t, requireMap(t, schemas, "FeedStatusResponse"), "properties")
	responseStatus := requireMap(t, feedStatusResponseProperties, "status")
	responseStatusEnums := requireStringEnum(t, responseStatus, "FeedStatusResponse.status")
	for _, want := range []string{"healthy", "degraded"} {
		if _, ok := responseStatusEnums[want]; !ok {
			t.Fatalf("FeedStatusResponse.status enum missing %q; got %v", want, enumKeys(responseStatusEnums))
		}
	}
	responseMessage := requireMap(t, feedStatusResponseProperties, "message")
	if got := responseMessage["type"]; got != "string" {
		t.Fatalf("FeedStatusResponse.message type = %#v, want string", got)
	}
}

func TestOpenAPI32UsesJSONSchemaNullTypes(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	if strings.Contains(string(data), "nullable:") {
		t.Fatal("OpenAPI 3.2 spec must use JSON Schema null union types instead of nullable")
	}
}

func TestOpenAPIFileValidatesAgainstOpenAPI32Standard(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	if err := validateOpenAPI32Document(data); err != nil {
		t.Fatalf("OpenAPI spec failed OpenAPI 3.2 validation: %v", err)
	}
}

func TestOpenAPI32StandardValidationRejectsInvalidDocument(t *testing.T) {
	invalid := []byte(`openapi: "3.2.0"
info:
  title: Invalid API
  version: "1.0.0"
paths: []
`)
	err := validateOpenAPI32Document(invalid)
	if err == nil {
		t.Fatal("validateOpenAPI32Document(invalid paths shape) = nil, want error")
	}
	if !strings.Contains(err.Error(), "OpenAPI 3.2 schema") {
		t.Fatalf("validation error = %v, want OpenAPI 3.2 schema error", err)
	}
}

func TestOpenAPICISAKEVClearMissingRequiresCVEs(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	cisaKEV := requireMap(t, schemas, "CISAKEVImportRequest")

	condition := requireMap(t, cisaKEV, "if")
	requireRequiredFields(t, condition, "CISAKEVImportRequest.if", "clear_missing")
	conditionProperties := requireMap(t, condition, "properties")
	clearMissing := requireMap(t, conditionProperties, "clear_missing")
	if got := clearMissing["const"]; got != true {
		t.Fatalf("CISAKEVImportRequest.if.clear_missing const = %#v, want true", got)
	}

	thenClause := requireMap(t, cisaKEV, "then")
	requireRequiredFields(t, thenClause, "CISAKEVImportRequest.then", "cve_ids")
	thenProperties := requireMap(t, thenClause, "properties")
	cveIDs := requireMap(t, thenProperties, "cve_ids")
	if got := requireInt(t, cveIDs, "minItems"); got != 1 {
		t.Fatalf("CISAKEVImportRequest.then.cve_ids minItems = %d, want 1", got)
	}
}

func TestOpenAPIScanPackageSchemaInstances(t *testing.T) {
	compiler := newOpenAPIInstanceCompiler(t)
	schema := compileOpenAPIFragment(t, compiler, "#/components/schemas/ScanPackage")

	tests := []struct {
		name         string
		packageName  string
		version      string
		wantAccepted bool
	}{
		{name: "ordinary coordinate", packageName: "left-pad", version: "1.0.0", wantAccepted: true},
		{name: "blank name", packageName: " \t ", version: "1.0.0", wantAccepted: false},
		{name: "blank version", packageName: "left-pad", version: " \t ", wantAccepted: false},
		{name: "embedded version whitespace", packageName: "left-pad", version: "1.0 0", wantAccepted: false},
		{name: "exact ASCII name code-point limit", packageName: strings.Repeat("n", checkcontract.MaxScanPackageNameCodePoints), version: "1.0.0", wantAccepted: true},
		{name: "over ASCII name code-point limit", packageName: strings.Repeat("n", checkcontract.MaxScanPackageNameCodePoints+1), version: "1.0.0", wantAccepted: false},
		{name: "exact ASCII version code-point limit", packageName: "left-pad", version: strings.Repeat("1", checkcontract.MaxScanPackageVersionCodePoints), wantAccepted: true},
		{name: "over ASCII version code-point limit", packageName: "left-pad", version: strings.Repeat("1", checkcontract.MaxScanPackageVersionCodePoints+1), wantAccepted: false},
		{name: "exact two-byte name code-point limit", packageName: strings.Repeat("é", checkcontract.MaxScanPackageNameCodePoints), version: "1.0.0", wantAccepted: true},
		{name: "over two-byte name code-point limit", packageName: strings.Repeat("é", checkcontract.MaxScanPackageNameCodePoints+1), version: "1.0.0", wantAccepted: false},
		{name: "exact two-byte version code-point limit", packageName: "left-pad", version: strings.Repeat("é", checkcontract.MaxScanPackageVersionCodePoints), wantAccepted: true},
		{name: "over two-byte version code-point limit", packageName: "left-pad", version: strings.Repeat("é", checkcontract.MaxScanPackageVersionCodePoints+1), wantAccepted: false},
		{name: "exact supplementary name code-point limit", packageName: strings.Repeat("\U0001F600", checkcontract.MaxScanPackageNameCodePoints), version: "1.0.0", wantAccepted: true},
		{name: "over supplementary name code-point limit", packageName: strings.Repeat("\U0001F600", checkcontract.MaxScanPackageNameCodePoints+1), version: "1.0.0", wantAccepted: false},
		{name: "exact supplementary version code-point limit", packageName: "left-pad", version: strings.Repeat("\U0001F600", checkcontract.MaxScanPackageVersionCodePoints), wantAccepted: true},
		{name: "over supplementary version code-point limit", packageName: "left-pad", version: strings.Repeat("\U0001F600", checkcontract.MaxScanPackageVersionCodePoints+1), wantAccepted: false},
		{name: "exact raw name limit includes whitespace", packageName: " " + strings.Repeat("n", checkcontract.MaxScanPackageNameCodePoints-2) + " ", version: "1.0.0", wantAccepted: true},
		{name: "name whitespace pushes raw value over limit", packageName: " " + strings.Repeat("n", checkcontract.MaxScanPackageNameCodePoints) + " ", version: "1.0.0", wantAccepted: false},
		{name: "exact raw version limit includes whitespace", packageName: "left-pad", version: " " + strings.Repeat("1", checkcontract.MaxScanPackageVersionCodePoints-2) + " ", wantAccepted: true},
		{name: "version whitespace pushes raw value over limit", packageName: "left-pad", version: " " + strings.Repeat("1", checkcontract.MaxScanPackageVersionCodePoints) + " ", wantAccepted: false},
		{name: "exact raw name may shrink during canonicalization", packageName: strings.Repeat("_", checkcontract.MaxScanPackageNameCodePoints), version: "1.0.0", wantAccepted: true},
		{name: "canonicalization cannot shrink raw over-limit name", packageName: strings.Repeat("_", checkcontract.MaxScanPackageNameCodePoints+1), version: "1.0.0", wantAccepted: false},
		{name: "ordinary surrounding whitespace", packageName: " left-pad ", version: " 1.0.0 ", wantAccepted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := map[string]any{"ecosystem": "npm", "name": tt.packageName, "version": tt.version}
			gotAccepted := schema.Validate(instance) == nil
			if gotAccepted != tt.wantAccepted {
				t.Fatalf("ScanPackage schema accepted = %t, want %t for %#v", gotAccepted, tt.wantAccepted, instance)
			}
			gotRuntimeAccepted := runtimeCheckCoordinateAccepted(tt.packageName, tt.version)
			if gotRuntimeAccepted != tt.wantAccepted || gotRuntimeAccepted != gotAccepted {
				t.Fatalf("ScanPackage schema/runtime accepted = %t/%t, want %t for %#v", gotAccepted, gotRuntimeAccepted, tt.wantAccepted, instance)
			}
		})
	}
}

func TestOpenAPICISAKEVClearMissingTruthTable(t *testing.T) {
	compiler := newOpenAPIInstanceCompiler(t)
	schema := compileOpenAPIFragment(t, compiler, "#/components/schemas/CISAKEVImportRequest")

	for _, tt := range []struct {
		name         string
		instance     map[string]any
		wantAccepted bool
	}{
		{name: "true with absent cve_ids", instance: map[string]any{"clear_missing": true}, wantAccepted: false},
		{name: "true with empty cve_ids", instance: map[string]any{"clear_missing": true, "cve_ids": []any{}}, wantAccepted: false},
		{name: "true with nonempty cve_ids", instance: map[string]any{"clear_missing": true, "cve_ids": []any{"CVE-2026-1001"}}, wantAccepted: true},
		{name: "false with absent cve_ids", instance: map[string]any{"clear_missing": false}, wantAccepted: true},
		{name: "false with empty cve_ids", instance: map[string]any{"clear_missing": false, "cve_ids": []any{}}, wantAccepted: true},
		{name: "false with nonempty cve_ids", instance: map[string]any{"clear_missing": false, "cve_ids": []any{"CVE-2026-1002"}}, wantAccepted: true},
		{name: "absent clear_missing and cve_ids", instance: map[string]any{}, wantAccepted: true},
		{name: "absent clear_missing with empty cve_ids", instance: map[string]any{"cve_ids": []any{}}, wantAccepted: true},
		{name: "absent clear_missing with nonempty cve_ids", instance: map[string]any{"cve_ids": []any{"CVE-2026-1003"}}, wantAccepted: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gotAccepted := schema.Validate(tt.instance) == nil
			if gotAccepted != tt.wantAccepted {
				t.Fatalf("CISAKEVImportRequest accepted = %t, want %t for %#v", gotAccepted, tt.wantAccepted, tt.instance)
			}
		})
	}
}

func TestOpenAPIDocumentsV1CompatibilityPolicy(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	info := requireMap(t, spec, "info")
	description, _ := info["description"].(string)
	for _, want := range []string{
		"API v1 compatibility policy",
		"Additive response fields and enum values may be introduced within v1",
		"Breaking changes require a new major API path",
		"Deprecated fields stay documented with deprecated: true",
	} {
		if !strings.Contains(description, want) {
			t.Fatalf("info.description missing compatibility guidance %q: %q", want, description)
		}
	}

	policy := requireMap(t, spec, "x-packmon-compatibility-policy")
	if got := policy["api_version"]; got != "v1" {
		t.Fatalf("x-packmon-compatibility-policy.api_version = %#v, want v1", got)
	}
	for key, want := range map[string]string{
		"additive_changes": "permitted",
		"breaking_changes": "new major API path",
		"deprecation":      "deprecated: true",
	} {
		text, _ := policy[key].(string)
		if !strings.Contains(text, want) {
			t.Fatalf("x-packmon-compatibility-policy.%s missing %q: %q", key, want, text)
		}
	}
}

func TestOpenAPIScanResultAllowsCanonicalCLIModesAndStatuses(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	scanResult := requireMap(t, schemas, "ScanResult")
	requireRequiredFields(t, scanResult, "ScanResult",
		"scan_id",
		"mode",
		"scanned_at",
		"duration_ms",
		"packages_scanned",
		"findings_count",
		"findings_blocking",
		"block_threshold",
		"feed_status",
		"db_stale",
		"summary",
		"findings",
		"feed_versions",
		"manual_advisories_count",
	)
	properties := requireMap(t, scanResult, "properties")

	mode := requireMap(t, properties, "mode")
	modeEnums := requireStringEnum(t, mode, "ScanResult.mode")
	for _, want := range domain.ScanModeValues() {
		if _, ok := modeEnums[string(want)]; !ok {
			t.Errorf("ScanResult.mode enum missing %q; got %v", want, enumKeys(modeEnums))
		}
	}

	feedStatus := requireMap(t, properties, "feed_status")
	statusEnums := requireStringEnum(t, feedStatus, "ScanResult.feed_status")
	for _, want := range domain.ScanFeedStatusValues() {
		if _, ok := statusEnums[string(want)]; !ok {
			t.Errorf("ScanResult.feed_status enum missing %q; got %v", want, enumKeys(statusEnums))
		}
	}
	if got := feedStatus["type"]; got != "string" {
		t.Fatalf("ScanResult.feed_status type = %#v, want string", got)
	}
	blockThreshold := requireMap(t, properties, "block_threshold")
	thresholdEnums := requireStringEnum(t, blockThreshold, "ScanResult.block_threshold")
	for _, want := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"} {
		if _, ok := thresholdEnums[want]; !ok {
			t.Errorf("ScanResult.block_threshold enum missing %q; got %v", want, enumKeys(thresholdEnums))
		}
	}
	scanError := requireMap(t, properties, "scan_error")
	if got := scanError["type"]; got != "string" {
		t.Fatalf("ScanResult.scan_error type = %#v, want string", got)
	}
}

func TestOpenAPIScanRequestDocumentsPackageCoordinateLimits(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	scanRequest := requireMap(t, schemas, "ScanRequest")
	if got := requireBool(t, scanRequest, "additionalProperties"); got {
		t.Fatalf("ScanRequest.additionalProperties = %t, want false to match strict JSON decoding", got)
	}
	requestProperties := requireMap(t, scanRequest, "properties")
	packages := requireMap(t, requestProperties, "packages")
	if got := requireInt(t, packages, "minItems"); got != 1 {
		t.Fatalf("ScanRequest.packages minItems = %d, want 1", got)
	}
	if got := requireInt(t, packages, "maxItems"); got != checkcontract.MaxPackagesPerCheck {
		t.Fatalf("ScanRequest.packages maxItems = %d, want %d", got, checkcontract.MaxPackagesPerCheck)
	}
	packageItems := requireMap(t, packages, "items")
	if got := packageItems["$ref"]; got != "#/components/schemas/ScanPackage" {
		t.Fatalf("ScanRequest.packages item ref = %#v, want ScanPackage", got)
	}

	scanPackage := requireMap(t, schemas, "ScanPackage")
	if got := requireBool(t, scanPackage, "additionalProperties"); got {
		t.Fatalf("ScanPackage.additionalProperties = %t, want false to match strict JSON decoding", got)
	}
	requireRequiredFields(t, scanPackage, "ScanPackage", "name", "version", "ecosystem")
	scanProperties := requireMap(t, scanPackage, "properties")
	scanEcosystemProperty := requireMap(t, scanProperties, "ecosystem")
	if got := scanEcosystemProperty["$ref"]; got != "#/components/schemas/ScanEcosystem" {
		t.Fatalf("ScanPackage.ecosystem ref = %#v, want ScanEcosystem", got)
	}
	scanEcosystem := requireMap(t, schemas, "ScanEcosystem")
	scanEcosystemEnums := requireStringEnum(t, scanEcosystem, "ScanEcosystem")
	for _, inventoryOnly := range []domain.Ecosystem{domain.EcosystemDocker, domain.EcosystemChocolatey} {
		if _, ok := scanEcosystemEnums[string(inventoryOnly)]; ok {
			t.Fatalf("ScanEcosystem must not include inventory-only %q", inventoryOnly)
		}
	}

	name := requireMap(t, scanProperties, "name")
	if got := requireInt(t, name, "minLength"); got != 1 {
		t.Fatalf("ScanPackage.name minLength = %d, want 1", got)
	}
	if got := requireInt(t, name, "maxLength"); got != checkcontract.MaxScanPackageNameCodePoints {
		t.Fatalf("ScanPackage.name maxLength = %d, want %d", got, checkcontract.MaxScanPackageNameCodePoints)
	}
	if got := name["pattern"]; got != `.*\S.*` {
		t.Fatalf("ScanPackage.name pattern = %#v, want non-blank pattern", got)
	}
	nameDescription, _ := name["description"].(string)
	for _, want := range []string{"Unicode code points", "before trimming", "Surrounding whitespace counts"} {
		if !strings.Contains(nameDescription, want) {
			t.Fatalf("ScanPackage.name description missing %q contract guidance: %q", want, nameDescription)
		}
	}
	version := requireMap(t, scanProperties, "version")
	if got := requireInt(t, version, "minLength"); got != 1 {
		t.Fatalf("ScanPackage.version minLength = %d, want 1", got)
	}
	if got := requireInt(t, version, "maxLength"); got != checkcontract.MaxScanPackageVersionCodePoints {
		t.Fatalf("ScanPackage.version maxLength = %d, want %d", got, checkcontract.MaxScanPackageVersionCodePoints)
	}
	if got := version["pattern"]; got != `^\s*\S+\s*$` {
		t.Fatalf("ScanPackage.version pattern = %#v, want single-token version pattern", got)
	}
	versionDescription, _ := version["description"].(string)
	for _, want := range []string{"Unicode code points", "before trimming", "Surrounding whitespace counts"} {
		if !strings.Contains(versionDescription, want) {
			t.Fatalf("ScanPackage.version description missing %q contract guidance: %q", want, versionDescription)
		}
	}

	for _, field := range []string{"dev", "direct", "indirect", "optional", "peer"} {
		if _, ok := scanProperties[field]; ok {
			t.Fatalf("ScanPackage must not document graph field %q for ScanRequest", field)
		}
	}
	for _, field := range []string{"via", "parents"} {
		if _, ok := scanProperties[field]; ok {
			t.Fatalf("ScanPackage must not document graph field %q for ScanRequest", field)
		}
	}
	if _, ok := schemas["Package"]; ok {
		t.Fatal("OpenAPI components must not expose Package for ScanRequest graph metadata")
	}
	if _, ok := schemas["PackageParent"]; ok {
		t.Fatal("OpenAPI components must not expose PackageParent for ScanRequest graph metadata")
	}

	if _, ok := schemas["RepoInfo"]; ok {
		t.Fatal("OpenAPI components must not expose RepoInfo with branch/commit metadata; use RemoteRepoInfo")
	}

	repoProperty := requireMap(t, requestProperties, "repo")
	if got := repoProperty["$ref"]; got != "#/components/schemas/RemoteRepoInfo" {
		t.Fatalf("ScanRequest.repo ref = %#v, want RemoteRepoInfo so remote API metadata only exposes repository name", got)
	}
	remoteRepoInfo := requireMap(t, schemas, "RemoteRepoInfo")
	if got := requireBool(t, remoteRepoInfo, "additionalProperties"); got {
		t.Fatalf("RemoteRepoInfo.additionalProperties = %t, want false to match strict JSON decoding", got)
	}
	remoteRepoProps := requireMap(t, remoteRepoInfo, "properties")
	if _, ok := remoteRepoProps["name"]; !ok {
		t.Fatal("RemoteRepoInfo missing name property")
	}
	for _, forbidden := range []string{"branch", "commit"} {
		if _, ok := remoteRepoProps[forbidden]; ok {
			t.Fatalf("RemoteRepoInfo must not expose %s metadata on remote API", forbidden)
		}
	}
}

func TestOpenAPIFindingRiskTypeIncludesManualOther(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	finding := requireMap(t, schemas, "Finding")
	properties := requireMap(t, finding, "properties")
	riskType := requireMap(t, properties, "risk_type")
	riskTypeEnums := requireStringEnum(t, riskType, "Finding.risk_type")
	if _, ok := riskTypeEnums["other"]; !ok {
		t.Fatalf("Finding.risk_type enum missing %q; got %v", "other", enumKeys(riskTypeEnums))
	}
}

func TestOpenAPIDoesNotPublishMetricsOnMainAPIServer(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	if _, ok := paths["/metrics"]; ok {
		t.Fatal("OpenAPI main API server must not publish /metrics; metrics runs on the separate metrics listener")
	}
}

func TestOpenAPIErrorResponsesUseJSONErrorEnvelope(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	errorResponse := requireMap(t, schemas, "ErrorResponse")
	requireRequiredFields(t, errorResponse, "ErrorResponse", "error", "code")
	errorProperties := requireMap(t, errorResponse, "properties")
	errorField := requireMap(t, errorProperties, "error")
	if got := errorField["type"]; got != "string" {
		t.Fatalf("ErrorResponse.error type = %#v, want string", got)
	}
	codeField := requireMap(t, errorProperties, "code")
	if got := codeField["type"]; got != "string" {
		t.Fatalf("ErrorResponse.code type = %#v, want string", got)
	}
	codeEnums := requireStringEnum(t, codeField, "ErrorResponse.code")
	for _, want := range []string{"invalid_request", "auth_failed", "forbidden", "conflict", "rate_limited", "not_found", "unsupported", "service_unavailable", "internal_error"} {
		if _, ok := codeEnums[want]; !ok {
			t.Fatalf("ErrorResponse.code enum missing %q; got %v", want, enumKeys(codeEnums))
		}
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path     string
		method   string
		statuses []string
	}{
		{"/api/v1/check", "post", []string{"400", "401", "403", "409", "415", "429", "503", "500"}},
		{"/api/v1/feeds/status", "get", []string{"401", "403", "429", "500"}},
		{"/api/v1/feeds/{feed}/import", "post", []string{"400", "401", "403", "404", "415", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}", "get", []string{"400", "401", "403", "404", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}/refresh", "post", []string{"400", "401", "403", "409", "415", "429", "500"}},
		{"/api/v1/sync", "get", []string{"400", "401", "403", "429", "500"}},
	}
	for _, feedImport := range feedImportContractCases() {
		cases = append(cases, struct {
			path     string
			method   string
			statuses []string
		}{feedImport.path, "post", []string{"400", "401", "403", "415", "429", "500"}})
	}
	for _, tt := range cases {
		operation := requireMap(t, requireMap(t, paths, tt.path), tt.method)
		responses := requireMap(t, operation, "responses")
		for _, status := range tt.statuses {
			response := requireMap(t, responses, status)
			content := requireMap(t, response, "content")
			jsonContent := requireMap(t, content, "application/json")
			schema := requireMap(t, jsonContent, "schema")
			if got := schema["$ref"]; got != "#/components/schemas/ErrorResponse" {
				t.Fatalf("%s %s response %s schema ref = %#v, want ErrorResponse", tt.method, tt.path, status, got)
			}
		}
	}
}

func TestOpenAPIBlockThresholdDocumentsMalwareHistoryException(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	scanResult := requireMap(t, requireMap(t, requireMap(t, spec, "components"), "schemas"), "ScanResult")
	blockThreshold := requireMap(t, requireMap(t, scanResult, "properties"), "block_threshold")
	description, _ := blockThreshold["description"].(string)
	for _, want := range []string{"malware_history", "LOW", "never block"} {
		if !strings.Contains(description, want) {
			t.Fatalf("ScanResult.block_threshold description must document the informational malware_history exception (missing %q): %q", want, description)
		}
	}
}

func TestOpenAPIRefreshDocumentsOptionalEmptyObjectBody(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	refresh := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/packages/{ecosystem}/{rest}/refresh"), "post")
	requestBody := requireMap(t, refresh, "requestBody")
	if required, _ := requestBody["required"].(bool); required {
		t.Fatal("refresh request body must be optional")
	}
	schema := requireMap(t, requireMap(t, requireMap(t, requestBody, "content"), "application/json"), "schema")
	if schema["type"] != "object" || schema["additionalProperties"] != false || schema["maxProperties"] != 0 {
		t.Fatalf("refresh request body schema = %#v, want an empty object (type object, additionalProperties false, maxProperties 0)", schema)
	}
}

func TestOpenAPIDocumentsAPIV1ResponseHeaders(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	headers := requireMap(t, requireMap(t, spec, "components"), "headers")
	correlationID := requireMap(t, headers, "CorrelationID")
	correlationSchema := requireMap(t, correlationID, "schema")
	if got := correlationSchema["type"]; got != "string" {
		t.Fatalf("CorrelationID header schema type = %#v, want string", got)
	}
	challenge := requireMap(t, headers, "BearerChallenge")
	challengeSchema := requireMap(t, challenge, "schema")
	if got := challengeSchema["type"]; got != "string" {
		t.Fatalf("BearerChallenge header schema type = %#v, want string", got)
	}
	if got := challengeSchema["example"]; got != `Bearer realm="packmon-api"` {
		t.Fatalf("BearerChallenge example = %#v, want Packmon bearer realm", got)
	}

	paths := requireMap(t, spec, "paths")
	for path, rawPathItem := range paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			t.Fatalf("path item %s = %#v, want map", path, rawPathItem)
		}
		for method, rawOperation := range pathItem {
			if method != "get" && method != "post" && method != "head" {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				t.Fatalf("%s %s operation = %#v, want map", method, path, rawOperation)
			}
			responses := requireMap(t, operation, "responses")
			for status, rawResponse := range responses {
				response, ok := rawResponse.(map[string]any)
				if !ok {
					t.Fatalf("%s %s response %s = %#v, want map", method, path, status, rawResponse)
				}
				requireResponseHeaderRef(t, response, "X-Correlation-ID", "#/components/headers/CorrelationID")
				if status == "401" {
					requireResponseHeaderRef(t, response, "WWW-Authenticate", "#/components/headers/BearerChallenge")
				}
			}
		}
	}
}

func TestOpenAPIDocumentsRequiredAPIUserAgent(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	components := requireMap(t, spec, "components")
	parameters := requireMap(t, components, "parameters")
	userAgent := requireMap(t, parameters, "PackmonUserAgent")
	if got := userAgent["name"]; got != "User-Agent" {
		t.Fatalf("PackmonUserAgent name = %#v, want User-Agent", got)
	}
	if got := userAgent["in"]; got != "header" {
		t.Fatalf("PackmonUserAgent in = %#v, want header", got)
	}
	if required, ok := userAgent["required"].(bool); !ok || !required {
		t.Fatalf("PackmonUserAgent required = %#v, want true", userAgent["required"])
	}
	description, _ := userAgent["description"].(string)
	for _, want := range []string{"Production", "packmon-cli/", "packmon-n8n/"} {
		if !strings.Contains(description, want) {
			t.Fatalf("PackmonUserAgent description missing %q: %q", want, description)
		}
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path   string
		method string
	}{
		{"/api/v1/check", "post"},
		{"/api/v1/feeds/status", "get"},
		{"/api/v1/feeds/status", "head"},
		{"/api/v1/feeds/{feed}/import", "post"},
		{"/api/v1/packages/{ecosystem}/{rest}", "get"},
		{"/api/v1/packages/{ecosystem}/{rest}", "head"},
		{"/api/v1/packages/{ecosystem}/{rest}/refresh", "post"},
		{"/api/v1/sync", "get"},
		{"/api/v1/sync", "head"},
	}
	for _, feedImport := range feedImportContractCases() {
		cases = append(cases, struct {
			path   string
			method string
		}{feedImport.path, "post"})
	}
	for _, tt := range cases {
		operation := requireMap(t, requireMap(t, paths, tt.path), tt.method)
		if !operationHasParameterRef(operation, "#/components/parameters/PackmonUserAgent") {
			t.Fatalf("%s %s missing PackmonUserAgent parameter ref", tt.method, tt.path)
		}
	}
}

func TestOpenAPIDocumentsOperationalHEADMethods(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path     string
		statuses []string
	}{
		{"/healthz", []string{"200"}},
		{"/readyz", []string{"200", "503"}},
		{"/version", []string{"200"}},
	}
	for _, tt := range cases {
		operation := requireMap(t, requireMap(t, paths, tt.path), "head")
		security, ok := operation["security"].([]any)
		if !ok || len(security) != 0 {
			t.Fatalf("HEAD %s security = %#v, want explicit public security []", tt.path, operation["security"])
		}
		responses := requireMap(t, operation, "responses")
		for _, status := range tt.statuses {
			response := requireMap(t, responses, status)
			if _, ok := response["content"]; ok {
				t.Fatalf("HEAD %s response %s documents body content: %#v", tt.path, status, response["content"])
			}
		}
	}
}

func TestOpenAPISecurityInheritanceMatrix(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	globalSecurity, ok := spec["security"].([]any)
	if !ok || len(globalSecurity) != 1 {
		t.Fatalf("global security = %#v, want one bearerAuth requirement", spec["security"])
	}
	requirement, ok := globalSecurity[0].(map[string]any)
	if !ok || len(requirement) != 1 {
		t.Fatalf("global security requirement = %#v, want only bearerAuth", globalSecurity[0])
	}
	scopes, ok := requirement["bearerAuth"].([]any)
	if !ok || len(scopes) != 0 {
		t.Fatalf("global bearerAuth scopes = %#v, want empty array", requirement["bearerAuth"])
	}

	protected := map[string]bool{
		"post /api/v1/check":                               true,
		"get /api/v1/feeds/status":                         true,
		"head /api/v1/feeds/status":                        true,
		"post /api/v1/feeds/{feed}/import":                 true,
		"get /api/v1/packages/{ecosystem}/{rest}":          true,
		"head /api/v1/packages/{ecosystem}/{rest}":         true,
		"post /api/v1/packages/{ecosystem}/{rest}/refresh": true,
		"get /api/v1/sync":                                 true,
		"head /api/v1/sync":                                true,
		"get /healthz":                                     false,
		"head /healthz":                                    false,
		"get /readyz":                                      false,
		"head /readyz":                                     false,
		"get /version":                                     false,
		"head /version":                                    false,
	}
	for _, feedImport := range feedImportContractCases() {
		protected["post "+feedImport.path] = true
	}
	paths := requireMap(t, spec, "paths")
	actualOperations := make(map[string]struct{}, len(protected))
	for path, rawPathItem := range paths {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			t.Fatalf("path item %s = %#v, want object", path, rawPathItem)
		}
		for _, method := range []string{"get", "head", "post", "put", "patch", "delete", "options", "trace", "query"} {
			if _, exists := pathItem[method]; exists {
				actualOperations[method+" "+path] = struct{}{}
			}
		}
	}
	if len(actualOperations) != len(protected) {
		t.Fatalf("documented path-operation count = %d (%v), want exhaustive %d", len(actualOperations), enumKeys(actualOperations), len(protected))
	}
	for operationKey := range actualOperations {
		if _, ok := protected[operationKey]; !ok {
			t.Fatalf("security matrix missing documented operation %q", operationKey)
		}
	}
	for operationKey, wantProtected := range protected {
		parts := strings.SplitN(operationKey, " ", 2)
		operation := requireMap(t, requireMap(t, paths, parts[1]), parts[0])
		security, hasOverride := operation["security"]
		if wantProtected {
			if hasOverride {
				t.Fatalf("%s security = %#v, want no override so global bearerAuth is inherited", operationKey, security)
			}
			continue
		}
		publicSecurity, ok := security.([]any)
		if !hasOverride || !ok || len(publicSecurity) != 0 {
			t.Fatalf("%s security = %#v, want explicit public security []", operationKey, security)
		}
	}

	webhookPost := requireMap(t, requireMap(t, requireMap(t, spec, "webhooks"), "scanCompleted"), "post")
	webhookSecurity, ok := webhookPost["security"].([]any)
	if !ok || len(webhookSecurity) != 0 {
		t.Fatalf("scanCompleted webhook security = %#v, want separate explicit []", webhookPost["security"])
	}
}

func TestOpenAPIOperationIDsAreUnique(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	seen := make(map[string]string)
	methods := []string{"get", "head", "post", "put", "patch", "delete", "options", "trace", "query"}
	checkPathItems := func(group string, pathItems map[string]any) {
		t.Helper()
		for path, rawPathItem := range pathItems {
			pathItem, ok := rawPathItem.(map[string]any)
			if !ok {
				t.Fatalf("%s path item %s = %#v, want object", group, path, rawPathItem)
			}
			for _, method := range methods {
				rawOperation, exists := pathItem[method]
				if !exists {
					continue
				}
				operation, ok := rawOperation.(map[string]any)
				if !ok {
					t.Fatalf("%s %s %s operation = %#v, want object", group, method, path, rawOperation)
				}
				operationID, ok := operation["operationId"].(string)
				if !ok || operationID == "" {
					t.Fatalf("%s %s %s operationId = %#v, want nonempty string", group, method, path, operation["operationId"])
				}
				location := group + " " + method + " " + path
				if previous, duplicate := seen[operationID]; duplicate {
					t.Fatalf("operationId %q is duplicated by %s and %s", operationID, previous, location)
				}
				seen[operationID] = location
			}
		}
	}
	checkPathItems("path", requireMap(t, spec, "paths"))
	checkPathItems("webhook", requireMap(t, spec, "webhooks"))
}

func TestOpenAPIDocumentsHEADForGETResources(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path     string
		statuses []string
	}{
		{"/api/v1/feeds/status", []string{"200", "401", "403", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}", []string{"200", "400", "401", "403", "404", "429", "500"}},
		{"/api/v1/sync", []string{"200", "400", "401", "403", "429", "500"}},
	}
	for _, tt := range cases {
		operation := requireMap(t, requireMap(t, paths, tt.path), "head")
		responses := requireMap(t, operation, "responses")
		for _, status := range tt.statuses {
			response := requireMap(t, responses, status)
			if _, ok := response["content"]; ok {
				t.Fatalf("HEAD %s response %s documents body content: %#v", tt.path, status, response["content"])
			}
		}
	}
}

func TestOpenAPICheckEndpointProvidesRequestAndResponseExamples(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	checkOperation := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/check"), "post")
	requestMedia := requireMap(t, requireMap(t, requireMap(t, checkOperation, "requestBody"), "content"), "application/json")
	requestExample := requireMap(t, requireMap(t, requestMedia, "examples"), "npmVulnerabilityCheck")
	requestValue := requireMap(t, requestExample, "value")
	packages, ok := requestValue["packages"].([]any)
	if !ok || len(packages) != 1 {
		t.Fatalf("check request example packages = %#v, want one package", requestValue["packages"])
	}
	packageValue, ok := packages[0].(map[string]any)
	if !ok {
		t.Fatalf("check request package example = %#v, want object", packages[0])
	}
	for field, want := range map[string]string{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"} {
		if got := packageValue[field]; got != want {
			t.Fatalf("check request package %s = %#v, want %q", field, got, want)
		}
	}

	okResponse := requireMap(t, requireMap(t, checkOperation, "responses"), "200")
	responseMedia := requireMap(t, requireMap(t, okResponse, "content"), "application/json")
	responseExample := requireMap(t, requireMap(t, responseMedia, "examples"), "blockingFinding")
	responseValue := requireMap(t, responseExample, "value")
	for _, field := range []string{"scan_id", "mode", "packages_scanned", "findings_blocking", "block_threshold", "feed_status", "summary", "findings"} {
		if _, ok := responseValue[field]; !ok {
			t.Fatalf("check 200 response example missing %q: %#v", field, responseValue)
		}
	}
}

func TestOpenAPIDocumentsCheckIdempotency(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	components := requireMap(t, spec, "components")
	parameters := requireMap(t, components, "parameters")
	idempotencyKey := requireMap(t, parameters, "IdempotencyKey")
	if got := idempotencyKey["name"]; got != "Idempotency-Key" {
		t.Fatalf("IdempotencyKey name = %#v, want Idempotency-Key", got)
	}
	if got := idempotencyKey["in"]; got != "header" {
		t.Fatalf("IdempotencyKey in = %#v, want header", got)
	}
	if required, ok := idempotencyKey["required"].(bool); !ok || required {
		t.Fatalf("IdempotencyKey required = %#v, want false", idempotencyKey["required"])
	}
	description, _ := idempotencyKey["description"].(string)
	for _, want := range []string{"same scan_id", "scan_log", "409"} {
		if !strings.Contains(description, want) {
			t.Fatalf("IdempotencyKey description missing %q: %q", want, description)
		}
	}
	schema := requireMap(t, idempotencyKey, "schema")
	if got := schema["type"]; got != "string" {
		t.Fatalf("IdempotencyKey schema type = %#v, want string", got)
	}
	if got := requireInt(t, schema, "maxLength"); got != 128 {
		t.Fatalf("IdempotencyKey maxLength = %d, want 128", got)
	}
	if got := schema["pattern"]; got != "^[A-Za-z0-9_.:-]+$" {
		t.Fatalf("IdempotencyKey pattern = %#v, want allowed header-key pattern", got)
	}

	checkOperation := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/check"), "post")
	if !operationHasParameterRef(checkOperation, "#/components/parameters/IdempotencyKey") {
		t.Fatal("POST /api/v1/check missing IdempotencyKey parameter ref")
	}
	responses := requireMap(t, checkOperation, "responses")
	okResponse := requireMap(t, responses, "200")
	headers := requireMap(t, okResponse, "headers")
	if _, ok := headers["Idempotency-Key"]; !ok {
		t.Fatalf("POST /api/v1/check 200 headers missing Idempotency-Key: %#v", headers)
	}
	conflict := requireMap(t, responses, "409")
	content := requireMap(t, conflict, "content")
	jsonContent := requireMap(t, content, "application/json")
	conflictSchema := requireMap(t, jsonContent, "schema")
	if got := conflictSchema["$ref"]; got != "#/components/schemas/ErrorResponse" {
		t.Fatalf("POST /api/v1/check 409 schema ref = %#v, want ErrorResponse", got)
	}
}

func TestOpenAPIDocumentsOperationResponseSchemas(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path   string
		method string
		status string
		ref    string
	}{
		{"/healthz", "get", "200", "#/components/schemas/HealthResponse"},
		{"/readyz", "get", "200", "#/components/schemas/ReadyResponse"},
		{"/readyz", "get", "503", "#/components/schemas/ReadyResponse"},
		{"/version", "get", "200", "#/components/schemas/VersionResponse"},
		{"/api/v1/packages/{ecosystem}/{rest}/refresh", "post", "202", "#/components/schemas/RefreshResponse"},
	}
	for _, tt := range cases {
		operation := requireMap(t, requireMap(t, paths, tt.path), tt.method)
		response := requireMap(t, requireMap(t, operation, "responses"), tt.status)
		content := requireMap(t, response, "content")
		jsonContent := requireMap(t, content, "application/json")
		schema := requireMap(t, jsonContent, "schema")
		if got := schema["$ref"]; got != tt.ref {
			t.Fatalf("%s %s response %s schema ref = %#v, want %s", tt.method, tt.path, tt.status, got, tt.ref)
		}
	}
	refreshResponses := requireMap(t, requireMap(t, requireMap(t, paths, "/api/v1/packages/{ecosystem}/{rest}/refresh"), "post"), "responses")
	if _, ok := refreshResponses["200"]; ok {
		t.Fatal("package refresh must document 202 Accepted, not 200 OK")
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	health := requireMap(t, schemas, "HealthResponse")
	requireRequiredFields(t, health, "HealthResponse", "status")
	healthStatus := requireMap(t, requireMap(t, health, "properties"), "status")
	healthEnums := requireStringEnum(t, healthStatus, "HealthResponse.status")
	if _, ok := healthEnums["ok"]; !ok {
		t.Fatalf("HealthResponse.status enum missing ok; got %v", enumKeys(healthEnums))
	}

	ready := requireMap(t, schemas, "ReadyResponse")
	requireRequiredFields(t, ready, "ReadyResponse", "status")
	readyProperties := requireMap(t, ready, "properties")
	readyStatus := requireMap(t, readyProperties, "status")
	readyEnums := requireStringEnum(t, readyStatus, "ReadyResponse.status")
	for _, want := range []string{"ready", "unavailable"} {
		if _, ok := readyEnums[want]; !ok {
			t.Fatalf("ReadyResponse.status enum missing %q; got %v", want, enumKeys(readyEnums))
		}
	}
	reason := requireMap(t, readyProperties, "reason")
	if got := reason["type"]; got != "string" {
		t.Fatalf("ReadyResponse.reason type = %#v, want string", got)
	}

	version := requireMap(t, schemas, "VersionResponse")
	requireRequiredFields(t, version, "VersionResponse", "version", "commit", "date")
	versionProperties := requireMap(t, version, "properties")
	for _, field := range []string{"version", "commit", "date"} {
		property := requireMap(t, versionProperties, field)
		if got := property["type"]; got != "string" {
			t.Fatalf("VersionResponse.%s type = %#v, want string", field, got)
		}
	}
}

func TestOpenAPIExposesWebhookContract(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	webhooks := requireMap(t, spec, "webhooks")
	scanCompleted := requireMap(t, webhooks, "scanCompleted")
	post := requireMap(t, scanCompleted, "post")
	security, ok := post["security"].([]any)
	if !ok || len(security) != 0 {
		t.Fatalf("webhook security = %#v, want explicit [] so receiver callbacks do not inherit API bearer auth", post["security"])
	}

	requestBody := requireMap(t, post, "requestBody")
	content := requireMap(t, requestBody, "content")
	jsonContent := requireMap(t, content, "application/json")
	schema := requireMap(t, jsonContent, "schema")
	if got := schema["$ref"]; got != "#/components/schemas/WebhookEnvelope" {
		t.Fatalf("webhook request schema ref = %#v, want WebhookEnvelope", got)
	}

	signatureHeader := requireOperationParameter(t, post, "X-Packmon-Signature", "header")
	if required, ok := signatureHeader["required"].(bool); !ok || required {
		t.Fatalf("X-Packmon-Signature required = %#v, want false", signatureHeader["required"])
	}
	description, _ := signatureHeader["description"].(string)
	for _, want := range []string{"HMAC", "sha256=", "shared secret"} {
		if !strings.Contains(description, want) {
			t.Fatalf("X-Packmon-Signature description missing %q: %q", want, description)
		}
	}

	responses := requireMap(t, post, "responses")
	if _, ok := responses["2XX"]; !ok {
		t.Fatalf("webhook responses missing 2XX receiver success response: %#v", responses)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	envelope := requireMap(t, schemas, "WebhookEnvelope")
	requireRequiredFields(t, envelope, "WebhookEnvelope", "event", "version", "timestamp", "source", "result")
	properties := requireMap(t, envelope, "properties")
	repository := requireMap(t, properties, "repository")
	if got := repository["$ref"]; got != "#/components/schemas/RemoteRepoInfo" {
		t.Fatalf("WebhookEnvelope.repository ref = %#v, want RemoteRepoInfo", got)
	}
	result := requireMap(t, properties, "result")
	if got := result["$ref"]; got != "#/components/schemas/ScanResult" {
		t.Fatalf("WebhookEnvelope.result ref = %#v, want ScanResult", got)
	}
	event := requireMap(t, properties, "event")
	eventEnums := requireStringEnum(t, event, "WebhookEnvelope.event")
	if _, ok := eventEnums["scan_completed"]; !ok {
		t.Fatalf("WebhookEnvelope.event enum missing scan_completed; got %v", enumKeys(eventEnums))
	}
	version := requireMap(t, properties, "version")
	if got := version["type"]; got != "string" {
		t.Fatalf("WebhookEnvelope.version type = %#v, want string", got)
	}
	versionEnums := requireStringEnum(t, version, "WebhookEnvelope.version")
	if len(versionEnums) != 1 {
		t.Fatalf("WebhookEnvelope.version enum = %v, want only schema version 1", enumKeys(versionEnums))
	}
	if _, ok := versionEnums["1"]; !ok {
		t.Fatalf("WebhookEnvelope.version enum missing schema version 1; got %v", enumKeys(versionEnums))
	}
	versionDescription, _ := version["description"].(string)
	for _, want := range []string{"schema version", "WebhookEnvelope", "breaking envelope changes"} {
		if !strings.Contains(versionDescription, want) {
			t.Fatalf("WebhookEnvelope.version description missing %q: %q", want, versionDescription)
		}
	}
}

func TestOpenAPIRefreshEndpointUsesSupportedEcosystemEnum(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	refreshEcosystem := requireMap(t, schemas, "RefreshEcosystem")
	enums := requireStringEnum(t, refreshEcosystem, "RefreshEcosystem")
	wantSupported := []string{"npm", "pypi", "go", "maven", "cargo", "nuget", "composer", "gem"}
	if len(enums) != len(wantSupported) {
		t.Fatalf("RefreshEcosystem enum length = %d (%v), want %d supported Socket.dev ecosystems", len(enums), enumKeys(enums), len(wantSupported))
	}
	for _, want := range wantSupported {
		if _, ok := enums[want]; !ok {
			t.Fatalf("RefreshEcosystem enum missing %q; got %v", want, enumKeys(enums))
		}
	}
	for _, unsupported := range []string{"actions", "docker", "chocolatey", "pub", "cocoapods", "swiftpm", "hex", "cran"} {
		if _, ok := enums[unsupported]; ok {
			t.Fatalf("RefreshEcosystem enum includes unsupported refresh ecosystem %q", unsupported)
		}
	}

	refreshOperation := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/packages/{ecosystem}/{rest}/refresh"), "post")
	ecosystem := requireOperationParameter(t, refreshOperation, "ecosystem", "path")
	schema := requireMap(t, ecosystem, "schema")
	if got := schema["$ref"]; got != "#/components/schemas/RefreshEcosystem" {
		t.Fatalf("refresh ecosystem schema ref = %#v, want RefreshEcosystem", got)
	}
}

func TestEcosystemContractsIncludeDomainEcosystems(t *testing.T) {
	openAPIData, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(openAPIData, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	ecosystem := requireMap(t, schemas, "Ecosystem")
	enumValues, ok := ecosystem["enum"].([]any)
	if !ok {
		t.Fatalf("OpenAPI Ecosystem enum = %#v, want array", ecosystem["enum"])
	}
	openAPIEnums := make(map[string]struct{}, len(enumValues))
	for _, value := range enumValues {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("OpenAPI Ecosystem enum value = %#v, want string", value)
		}
		openAPIEnums[text] = struct{}{}
	}

	designData, err := os.ReadFile("../../DESIGN.md")
	if err != nil {
		t.Fatalf("read DESIGN.md: %v", err)
	}
	design := string(designData)
	start := strings.Index(design, "The canonical ecosystem identifiers are lowercase:")
	end := strings.Index(design, "Feed-specific names must be mapped into this enum")
	if start == -1 || end == -1 || end <= start {
		t.Fatal("DESIGN.md supported ecosystem section not found")
	}
	designSection := design[start:end]

	for _, ecosystem := range []domain.Ecosystem{
		domain.EcosystemNPM,
		domain.EcosystemPyPI,
		domain.EcosystemGo,
		domain.EcosystemMaven,
		domain.EcosystemCargo,
		domain.EcosystemNuGet,
		domain.EcosystemComposer,
		domain.EcosystemGem,
		domain.EcosystemPub,
		domain.EcosystemGitHubActions,
		domain.EcosystemCocoaPods,
		domain.EcosystemSwiftPM,
		domain.EcosystemHex,
		domain.EcosystemCRAN,
		domain.EcosystemDocker,
		domain.EcosystemChocolatey,
	} {
		value := string(ecosystem)
		if _, ok := openAPIEnums[value]; !ok {
			t.Fatalf("OpenAPI Ecosystem enum missing %q", value)
		}
		if !strings.Contains(designSection, value) {
			t.Fatalf("DESIGN.md canonical ecosystem list missing %q", value)
		}
	}
}

func TestOpenAPIDocumentsFeedImportSchemas(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}
	paths := requireMap(t, spec, "paths")
	feedImport := requireMap(t, paths, "/api/v1/feeds/{feed}/import")
	post := requireMap(t, feedImport, "post")
	if got := post["operationId"]; got != "importFeed" {
		t.Fatalf("generic feed import operationId = %#v, want importFeed", got)
	}
	if deprecated, ok := post["deprecated"].(bool); !ok || !deprecated {
		t.Fatalf("generic feed import deprecated = %#v, want true", post["deprecated"])
	}
	feedParameter := requireOperationParameter(t, post, "feed", "path")
	feedDescription, _ := feedParameter["description"].(string)
	for _, want := range []string{"malicious", "deprecated legacy alias", "openssf"} {
		if !strings.Contains(feedDescription, want) {
			t.Fatalf("feed import path parameter description missing %q alias guidance: %q", want, feedDescription)
		}
	}
	feedSchema := requireMap(t, feedParameter, "schema")
	deprecatedValues := requireMap(t, feedSchema, "x-packmon-deprecated-values")
	maliciousDeprecation, _ := deprecatedValues["malicious"].(string)
	for _, want := range []string{"deprecated legacy alias", "openssf"} {
		if !strings.Contains(maliciousDeprecation, want) {
			t.Fatalf("feed import malicious enum deprecation missing %q: %q", want, maliciousDeprecation)
		}
	}

	operationDescription, _ := post["description"].(string)
	for _, want := range []string{"Deprecated", "concrete feed operation", "selector-specific schema"} {
		if !strings.Contains(operationDescription, want) {
			t.Fatalf("generic feed import operation description missing %q compatibility guidance: %q", want, operationDescription)
		}
	}
	requestBody := requireMap(t, post, "requestBody")
	requestBodyDescription, _ := requestBody["description"].(string)
	for _, want := range []string{
		"Compatibility",
		"concrete feed operation",
		"selector-specific request schema",
		"osv/ghsa",
		"openssf/malicious/socket",
		"vulncheck",
		"cisakev",
		"epss",
		"repeated top-level entries",
		"status member names",
		"buffered and streamed",
	} {
		if !strings.Contains(requestBodyDescription, want) {
			t.Fatalf("generic feed import request body description missing %q guidance: %q", want, requestBodyDescription)
		}
	}
	requestContent := requireMap(t, requireMap(t, requestBody, "content"), "application/json")
	requestSchema := requireMap(t, requestContent, "schema")
	if requestSchema["type"] != "object" {
		t.Fatalf("generic feed import request schema type = %#v, want object", requestSchema["type"])
	}
	for _, composition := range []string{"anyOf", "oneOf"} {
		if _, exists := requestSchema[composition]; exists {
			t.Fatalf("generic feed import request schema retains ambiguous %s: %#v", composition, requestSchema[composition])
		}
	}
	parameters, ok := post["parameters"].([]any)
	if !ok {
		t.Fatalf("feed import parameters = %#v, want array", post["parameters"])
	}
	hasImportSecretHeader := false
	for _, parameter := range parameters {
		param, ok := parameter.(map[string]any)
		if !ok {
			continue
		}
		if param["name"] == "X-Packmon-Feed-Import-Secret" && param["in"] == "header" {
			hasImportSecretHeader = true
			break
		}
	}
	if !hasImportSecretHeader {
		t.Fatal("feed import is missing X-Packmon-Feed-Import-Secret header parameter")
	}

	responses := requireMap(t, post, "responses")
	badRequestResponse := requireMap(t, responses, "400")
	badRequestDescription, _ := badRequestResponse["description"].(string)
	for _, want := range []string{"Repeated top-level entries or status", "VulnCheck and EPSS", "rejected-import"} {
		if !strings.Contains(badRequestDescription, want) {
			t.Fatalf("feed import 400 description missing duplicate-member policy %q: %q", want, badRequestDescription)
		}
	}
	okResponse := requireMap(t, responses, "200")
	responseContent := requireMap(t, requireMap(t, okResponse, "content"), "application/json")
	responseSchema := requireMap(t, responseContent, "schema")
	if got := responseSchema["$ref"]; got != "#/components/schemas/ImportResponse" {
		t.Fatalf("feed import 200 schema ref = %#v, want ImportResponse", got)
	}
	if _, ok := responses["403"]; !ok {
		t.Fatal("feed import is missing 403 response for invalid import secret")
	}
	if _, ok := responses["404"]; !ok {
		t.Fatal("feed import is missing 404 response for unknown feed path")
	}

	seenConcreteFeeds := make(map[string]struct{}, len(feedImportContractCases()))
	for _, tt := range feedImportContractCases() {
		operation := requireMap(t, requireMap(t, paths, tt.path), "post")
		seenConcreteFeeds[tt.feed] = struct{}{}
		if got := operation["operationId"]; got != tt.operationID {
			t.Fatalf("%s operationId = %#v, want %s", tt.path, got, tt.operationID)
		}
		deprecated, _ := operation["deprecated"].(bool)
		if deprecated != tt.deprecated {
			t.Fatalf("%s deprecated = %t, want %t", tt.path, deprecated, tt.deprecated)
		}
		if !operationHasParameterRef(operation, "#/components/parameters/PackmonUserAgent") {
			t.Fatalf("%s missing PackmonUserAgent parameter ref", tt.path)
		}
		operationParameters, ok := operation["parameters"].([]any)
		if !ok {
			t.Fatalf("%s parameters = %#v, want array", tt.path, operation["parameters"])
		}
		hasImportSecretHeader := false
		for _, rawParameter := range operationParameters {
			parameter, ok := rawParameter.(map[string]any)
			if ok && parameter["name"] == "X-Packmon-Feed-Import-Secret" && parameter["in"] == "header" {
				hasImportSecretHeader = true
			}
		}
		if !hasImportSecretHeader {
			t.Fatalf("%s is missing X-Packmon-Feed-Import-Secret header parameter", tt.path)
		}
		concreteRequestBody := requireMap(t, operation, "requestBody")
		concreteSchema := requireMap(t, requireMap(t, requireMap(t, concreteRequestBody, "content"), "application/json"), "schema")
		if got := concreteSchema["$ref"]; got != "#/components/schemas/"+tt.schemaName {
			t.Fatalf("%s request schema ref = %#v, want %s", tt.path, got, tt.schemaName)
		}
		concreteResponses := requireMap(t, operation, "responses")
		if _, ok := concreteResponses["404"]; ok {
			t.Fatalf("known-selector operation %s documents impossible unknown-feed 404", tt.path)
		}
		concreteOK := requireMap(t, concreteResponses, "200")
		concreteResponseSchema := requireMap(t, requireMap(t, requireMap(t, concreteOK, "content"), "application/json"), "schema")
		if got := concreteResponseSchema["$ref"]; got != "#/components/schemas/ImportResponse" {
			t.Fatalf("%s 200 schema ref = %#v, want ImportResponse", tt.path, got)
		}
	}
	if len(seenConcreteFeeds) != len(feedSchema["enum"].([]any)) {
		t.Fatalf("concrete feed import selectors = %v, want exact generic enum", enumKeys(seenConcreteFeeds))
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	for _, name := range []string{
		"ImportResponse",
		"FeedImportStatus",
		"VulnerabilityImportRequest",
		"MaliciousImportRequest",
		"VulnCheckImportRequest",
		"CISAKEVImportRequest",
		"EPSSImportRequest",
	} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("OpenAPI components missing %s", name)
		}
	}
	importResponse := requireMap(t, schemas, "ImportResponse")
	requireRequiredFields(t, importResponse, "ImportResponse", "feed", "imported", "deleted", "entries_total")
	importResponseProps := requireMap(t, importResponse, "properties")
	importResponseFeed := requireMap(t, importResponseProps, "feed")
	importResponseFeedDescription, _ := importResponseFeed["description"].(string)
	for _, want := range []string{"deprecated legacy alias", "malicious", "openssf"} {
		if !strings.Contains(importResponseFeedDescription, want) {
			t.Fatalf("ImportResponse.feed description missing %q alias guidance: %q", want, importResponseFeedDescription)
		}
	}

	feedImportStatus := requireMap(t, schemas, "FeedImportStatus")
	statusProps := requireMap(t, feedImportStatus, "properties")
	if lastError := requireMap(t, statusProps, "last_error"); lastError["maxLength"] != 2048 {
		t.Fatalf("FeedImportStatus.last_error maxLength = %#v, want 2048", lastError["maxLength"])
	}
	if lastEtag := requireMap(t, statusProps, "last_etag"); lastEtag["maxLength"] != 512 {
		t.Fatalf("FeedImportStatus.last_etag maxLength = %#v, want 512", lastEtag["maxLength"])
	}
	if lastCommit := requireMap(t, statusProps, "last_commit_hash"); lastCommit["maxLength"] != 128 {
		t.Fatalf("FeedImportStatus.last_commit_hash maxLength = %#v, want 128", lastCommit["maxLength"])
	}

	vulnCheckEntry := requireMap(t, schemas, "VulnCheckImportEntry")
	vulnCheckProps := requireMap(t, vulnCheckEntry, "properties")
	cvssScore := requireMap(t, vulnCheckProps, "cvss_score")
	if cvssScore["minimum"] != 0 || cvssScore["maximum"] != 10 {
		t.Fatalf("VulnCheckImportEntry.cvss_score bounds = min %#v max %#v, want 0..10", cvssScore["minimum"], cvssScore["maximum"])
	}

	epssEntry := requireMap(t, schemas, "EPSSImportEntry")
	epssProps := requireMap(t, epssEntry, "properties")
	for _, field := range []string{"score", "percentile"} {
		prop := requireMap(t, epssProps, field)
		if prop["minimum"] != 0 || prop["maximum"] != 1 {
			t.Fatalf("EPSSImportEntry.%s bounds = min %#v max %#v, want 0..1", field, prop["minimum"], prop["maximum"])
		}
	}
	epssRequest := requireMap(t, schemas, "EPSSImportRequest")
	requireRequiredFields(t, epssRequest, "EPSSImportRequest", "entries")
	epssRequestProps := requireMap(t, epssRequest, "properties")
	epssEntries := requireMap(t, epssRequestProps, "entries")
	if epssEntries["minItems"] != 1 {
		t.Fatalf("EPSSImportRequest.entries minItems = %#v, want 1", epssEntries["minItems"])
	}

	affectedPackage := requireMap(t, schemas, "AffectedPackage")
	affectedPackageProps := requireMap(t, affectedPackage, "properties")
	versionRanges := requireMap(t, affectedPackageProps, "version_ranges")
	if versionRanges["type"] != "array" {
		t.Fatalf("AffectedPackage.version_ranges type = %#v, want array", versionRanges["type"])
	}
	versionRangeItems := requireMap(t, versionRanges, "items")
	if versionRangeItems["$ref"] != "#/components/schemas/VersionRange" {
		t.Fatalf("AffectedPackage.version_ranges items ref = %#v, want VersionRange", versionRangeItems["$ref"])
	}
	versionsAffected := requireMap(t, affectedPackageProps, "versions_affected")
	if versionsAffected["type"] != "array" {
		t.Fatalf("AffectedPackage.versions_affected type = %#v, want array", versionsAffected["type"])
	}
	versionsAffectedItems := requireMap(t, versionsAffected, "items")
	if versionsAffectedItems["type"] != "string" {
		t.Fatalf("AffectedPackage.versions_affected items type = %#v, want string", versionsAffectedItems["type"])
	}
	versionRange := requireMap(t, schemas, "VersionRange")
	versionRangeProps := requireMap(t, versionRange, "properties")
	versionRangeEvents := requireMap(t, versionRangeProps, "events")
	if versionRangeEvents["minItems"] != 1 {
		t.Fatalf("VersionRange.events minItems = %#v, want 1", versionRangeEvents["minItems"])
	}

	maliciousImport := requireMap(t, schemas, "MaliciousImport")
	requireRequiredFields(t, maliciousImport, "MaliciousImport", "id", "ecosystem", "name")
	maliciousProps := requireMap(t, maliciousImport, "properties")
	maliciousSource := requireMap(t, maliciousProps, "source")
	if got := requireBool(t, maliciousSource, "deprecated"); !got {
		t.Fatalf("MaliciousImport.source deprecated = %t, want true", got)
	}
	maliciousSourceDescription, _ := maliciousSource["description"].(string)
	for _, want := range []string{"Deprecated compatibility input", "route feed"} {
		if !strings.Contains(maliciousSourceDescription, want) {
			t.Fatalf("MaliciousImport.source description missing %q deprecation guidance: %q", want, maliciousSourceDescription)
		}
	}
	versions := requireMap(t, maliciousProps, "versions")
	if versions["type"] != "array" {
		t.Fatalf("MaliciousImport.versions type = %#v, want array", versions["type"])
	}
	versionItems := requireMap(t, versions, "items")
	if versionItems["type"] != "string" {
		t.Fatalf("MaliciousImport.versions items type = %#v, want string", versionItems["type"])
	}

	vulnerabilityImport := requireMap(t, schemas, "VulnerabilityImport")
	vulnerabilityProps := requireMap(t, vulnerabilityImport, "properties")
	vulnerabilitySources := requireMap(t, vulnerabilityProps, "sources")
	if got := requireBool(t, vulnerabilitySources, "deprecated"); !got {
		t.Fatalf("VulnerabilityImport.sources deprecated = %t, want true", got)
	}
	vulnerabilitySourcesDescription, _ := vulnerabilitySources["description"].(string)
	for _, want := range []string{"Deprecated compatibility input", "route feed"} {
		if !strings.Contains(vulnerabilitySourcesDescription, want) {
			t.Fatalf("VulnerabilityImport.sources description missing %q deprecation guidance: %q", want, vulnerabilitySourcesDescription)
		}
	}
}

func TestOpenAPIFeedImportExactRequestReferences(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	paths := requireMap(t, spec, "paths")
	genericPost := requireMap(t, requireMap(t, paths, "/api/v1/feeds/{feed}/import"), "post")
	genericSchema := requireMap(t, requireMap(t, requireMap(t, requireMap(t, genericPost, "requestBody"), "content"), "application/json"), "schema")
	for _, composition := range []string{"anyOf", "oneOf"} {
		if _, exists := genericSchema[composition]; exists {
			t.Fatalf("generic feed import request retains %s ambiguity: %#v", composition, genericSchema[composition])
		}
	}

	seenPaths := make(map[string]struct{}, len(feedImportContractCases()))
	for _, tt := range feedImportContractCases() {
		if _, duplicate := seenPaths[tt.path]; duplicate {
			t.Fatalf("feed import contract matrix contains duplicate path %q", tt.path)
		}
		seenPaths[tt.path] = struct{}{}
		post := requireMap(t, requireMap(t, paths, tt.path), "post")
		requestSchema := requireMap(t, requireMap(t, requireMap(t, requireMap(t, post, "requestBody"), "content"), "application/json"), "schema")
		if len(requestSchema) != 1 {
			t.Fatalf("%s request schema = %#v, want direct reference only", tt.path, requestSchema)
		}
		if got := requestSchema["$ref"]; got != "#/components/schemas/"+tt.schemaName {
			t.Fatalf("%s request schema ref = %#v, want %s", tt.path, got, tt.schemaName)
		}
	}
}

func TestOpenAPIFeedImportSelectorSchemaMapping(t *testing.T) {
	compiler := newOpenAPIInstanceCompiler(t)
	tests := feedImportContractCases()
	if got := apiv1.FeedImportPathFeedNames(); len(got) != len(tests) {
		t.Fatalf("documented feed selector count = %d (%v), want exact %d-case schema matrix", len(got), got, len(tests))
	}

	seen := make(map[string]struct{}, len(tests))
	for _, tt := range tests {
		t.Run(tt.feed, func(t *testing.T) {
			seen[tt.feed] = struct{}{}
			fragment := "#/paths/" + openAPIJSONPointerToken(tt.path) + "/post/requestBody/content/application~1json/schema"
			schema := compileOpenAPIFragment(t, compiler, fragment)
			instance := decodeJSONInstance(t, tt.body)
			if err := schema.Validate(instance); err != nil {
				t.Fatalf("%s payload does not validate against concrete operation %s: %v", tt.feed, tt.path, err)
			}
			wrongInstance := decodeJSONInstance(t, tt.wrongBody)
			if err := schema.Validate(wrongInstance); err == nil {
				t.Fatalf("%s operation accepted payload for a different feed schema: %s", tt.path, tt.wrongBody)
			}
		})
	}
	documented := make(map[string]struct{}, len(tests))
	for _, feed := range apiv1.FeedImportPathFeedNames() {
		if _, duplicate := documented[feed]; duplicate {
			t.Fatalf("documented feed selectors contain duplicate %q", feed)
		}
		documented[feed] = struct{}{}
	}
	if !reflect.DeepEqual(seen, documented) {
		t.Fatalf("feed selector matrix = %v, want exact documented set %v", enumKeys(seen), enumKeys(documented))
	}
}

func TestOpenAPIFeedImportStatusOnlySchemaMatrix(t *testing.T) {
	compiler := newOpenAPIInstanceCompiler(t)
	statusOnly := decodeJSONInstance(t, `{"status":{"last_sync_status":"error","last_error":"status-only import"}}`)
	for _, tt := range feedImportContractCases() {
		t.Run(tt.feed, func(t *testing.T) {
			fragment := "#/paths/" + openAPIJSONPointerToken(tt.path) + "/post/requestBody/content/application~1json/schema"
			schema := compileOpenAPIFragment(t, compiler, fragment)
			gotAccepted := schema.Validate(statusOnly) == nil
			if gotAccepted != tt.statusOnlyAccepted {
				t.Fatalf("status-only %s operation accepted = %t, want %t", tt.path, gotAccepted, tt.statusOnlyAccepted)
			}
		})
	}

	spec := readOpenAPISpecMap(t)
	genericPost := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/feeds/{feed}/import"), "post")
	genericSchema := requireMap(t, requireMap(t, requireMap(t, requireMap(t, genericPost, "requestBody"), "content"), "application/json"), "schema")
	for _, composition := range []string{"anyOf", "oneOf"} {
		if _, exists := genericSchema[composition]; exists {
			t.Fatalf("generic feed import request retains ambiguous %s: %#v", composition, genericSchema[composition])
		}
	}
}

func TestOpenAPIPublishedExamplesValidateAgainstSchemas(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	paths := requireMap(t, spec, "paths")
	checkPost := requireMap(t, requireMap(t, paths, "/api/v1/check"), "post")
	checkRequestMedia := requireMap(t, requireMap(t, requireMap(t, checkPost, "requestBody"), "content"), "application/json")
	checkRequestExamples := requireMap(t, checkRequestMedia, "examples")
	checkRequestExample := requireMap(t, requireMap(t, checkRequestExamples, "npmVulnerabilityCheck"), "value")
	checkResponseMedia := requireMap(t, requireMap(t, requireMap(t, requireMap(t, requireMap(t, checkPost, "responses"), "200"), "content"), "application/json"), "examples")
	checkResponseExample := requireMap(t, requireMap(t, checkResponseMedia, "blockingFinding"), "value")

	packagePath := requireMap(t, paths, "/api/v1/packages/{ecosystem}/{rest}")
	packageGetRest := requireOperationParameter(t, requireMap(t, packagePath, "get"), "rest", "path")
	packageHeadRest := requireOperationParameter(t, requireMap(t, packagePath, "head"), "rest", "path")
	refreshRest := requireOperationParameter(t, requireMap(t, requireMap(t, paths, "/api/v1/packages/{ecosystem}/{rest}/refresh"), "post"), "rest", "path")
	bearerChallenge := requireMap(t, requireMap(t, requireMap(t, spec, "components"), "headers"), "BearerChallenge")

	examples := []struct {
		location string
		fragment string
		value    any
	}{
		{
			location: "paths//api/v1/check/post/requestBody/content/application/json/examples/npmVulnerabilityCheck/value",
			fragment: "#/paths/~1api~1v1~1check/post/requestBody/content/application~1json/schema",
			value:    checkRequestExample,
		},
		{
			location: "paths//api/v1/check/post/responses/200/content/application/json/examples/blockingFinding/value",
			fragment: "#/paths/~1api~1v1~1check/post/responses/200/content/application~1json/schema",
			value:    checkResponseExample,
		},
		{
			location: "paths//api/v1/packages/{ecosystem}/{rest}/get/parameters/2/example",
			fragment: "#/paths/~1api~1v1~1packages~1%7Becosystem%7D~1%7Brest%7D/get/parameters/2/schema",
			value:    packageGetRest["example"],
		},
		{
			location: "paths//api/v1/packages/{ecosystem}/{rest}/head/parameters/2/example",
			fragment: "#/paths/~1api~1v1~1packages~1%7Becosystem%7D~1%7Brest%7D/head/parameters/2/schema",
			value:    packageHeadRest["example"],
		},
		{
			location: "paths//api/v1/packages/{ecosystem}/{rest}/refresh/post/parameters/2/example",
			fragment: "#/paths/~1api~1v1~1packages~1%7Becosystem%7D~1%7Brest%7D~1refresh/post/parameters/2/schema",
			value:    refreshRest["example"],
		},
		{
			location: "components/headers/BearerChallenge/schema/example",
			fragment: "#/components/headers/BearerChallenge/schema",
			value:    requireMap(t, bearerChallenge, "schema")["example"],
		},
	}

	discovered := make(map[string]struct{})
	collectOpenAPIExampleLocations(spec, "", discovered)
	wantLocations := make(map[string]struct{}, len(examples))
	compiler := newOpenAPIInstanceCompiler(t)
	for _, example := range examples {
		wantLocations[example.location] = struct{}{}
		schema := compileOpenAPIFragment(t, compiler, example.fragment)
		if err := schema.Validate(example.value); err != nil {
			t.Errorf("published example %s does not validate against adjacent schema %s: %v", example.location, example.fragment, err)
		}
	}
	if !reflect.DeepEqual(discovered, wantLocations) {
		t.Fatalf("published semantic example locations = %v, want exact six locations %v", enumKeys(discovered), enumKeys(wantLocations))
	}
}

func TestOpenAPICanonicalWirePayloadsValidateAgainstSchemas(t *testing.T) {
	compiler := newOpenAPIInstanceCompiler(t)
	now := time.Date(2026, 11, 2, 12, 34, 56, 123456789, time.UTC)
	age := 2

	emptyResult := domain.ScanResult{
		ScanID:                "scan-empty",
		Mode:                  domain.ScanModeLocal,
		ScannedAt:             now,
		DurationMs:            5,
		PackagesScanned:       1,
		FindingsCount:         0,
		FindingsBlocking:      false,
		BlockThreshold:        domain.SeverityNone,
		FeedStatus:            string(domain.ScanFeedStatusHealthy),
		DBAgeDays:             &age,
		DBStale:               false,
		Summary:               domain.EmptyScanSummary(),
		Findings:              []domain.Finding{},
		ParseErrors:           []string{},
		FeedVersions:          map[string]string{},
		ManualAdvisoriesCount: 0,
	}
	finding := domain.Finding{
		Name:       "left-pad",
		Version:    "1.3.0",
		Ecosystem:  domain.EcosystemNPM,
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityHigh,
		AdvisoryID: "GHSA-canonical",
		Title:      "Canonical vulnerability",
		URL:        "https://example.test/advisories/GHSA-canonical",
		Source:     "osv",
	}
	degradedResult := emptyResult
	degradedResult.ScanID = "scan-degraded"
	degradedResult.Mode = domain.ScanModeRemote
	degradedResult.FeedStatus = string(domain.ScanFeedStatusDegraded)
	degradedResult.Findings = []domain.Finding{finding}
	degradedResult.FindingsCount = 1
	degradedResult.FindingsBlocking = true
	degradedResult.BlockThreshold = domain.SeverityHigh
	degradedResult.Summary = domain.BuildScanSummary(degradedResult.Findings)
	degradedResult.FeedVersions = map[string]string{"osv": now.Format(time.RFC3339Nano)}
	errorResult := emptyResult
	errorResult.ScanID = "scan-error"
	errorResult.Mode = domain.ScanModeAuto
	errorResult.FeedStatus = string(domain.ScanFeedStatusError)
	errorResult.ScanError = "feed unavailable"
	errorResult.DBStale = true

	validateMarshaledOpenAPIInstance(t, compiler, "#/components/schemas/ScanResult", emptyResult)
	validateMarshaledOpenAPIInstance(t, compiler, "#/components/schemas/ScanResult", degradedResult)
	validateMarshaledOpenAPIInstance(t, compiler, "#/components/schemas/ScanResult", errorResult)
	validateMarshaledOpenAPIInstance(t, compiler, "#/components/schemas/WebhookEnvelope", domain.WebhookEnvelope{
		Event:      "scan_completed",
		Version:    "1",
		Timestamp:  now,
		Source:     "packmon",
		Repository: &domain.RemoteRepoInfo{Name: "web-api"},
		Result:     degradedResult,
	})

	activeVulnerability := synccontract.Vulnerability{
		ID: "GHSA-active", Ecosystem: "npm", Name: "left-pad", VersionRanges: `[]`, VersionsAffected: `["1.3.0"]`, References: `[]`,
		Severity: "HIGH", CISAKEV: true, Summary: "active vulnerability", Source: "osv",
	}
	activeMalicious := synccontract.Malicious{
		ID: "MAL-active", Ecosystem: "npm", Name: "evil-package", VersionRanges: `[]`, Versions: `[]`, ReferenceURLs: `[]`,
		RiskType: "malware", Severity: "CRITICAL", Summary: "active malicious package", Source: "openssf",
	}
	activeReputation := synccontract.Reputation{
		ID: "RL-active", Ecosystem: "npm", Name: "history-package", Version: "1.0.0", Type: "supply_chain_risk",
		RiskType: domain.RiskTypeMalwareHistory, Severity: "LOW", Summary: "historical reputation context",
	}
	releaseDate := "2026-01-15"
	isEOES := false
	activeLifecycle := synccontract.Lifecycle{
		ID: "EOL-active", Ecosystem: "npm", Name: "node", ProductSlug: "nodejs", ProductLabel: "Node.js", Cycle: "24", Latest: "24.1.0",
		ReleaseDate: &releaseDate, IsLTS: true, LTSFrom: &releaseDate, IsEOAS: false, EOASFrom: nil, IsEOL: false, EOLFrom: nil,
		IsDiscontinued: false, DiscontinuedFrom: nil, IsEOES: &isEOES, EOESFrom: nil, IsMaintained: true,
	}
	withdrawnVulnerability := activeVulnerability
	withdrawnVulnerability.ID = "GHSA-withdrawn"
	withdrawnVulnerability.Withdrawn = true
	withdrawnMalicious := activeMalicious
	withdrawnMalicious.ID = "MAL-withdrawn"
	withdrawnMalicious.Withdrawn = true
	withdrawnReputation := synccontract.Reputation{ID: "RL-withdrawn", Ecosystem: "npm", Name: "removed", Withdrawn: true}
	nullLifecycle := synccontract.Lifecycle{
		ID: "EOL-null-dates", Ecosystem: "npm", Name: "runtime", ProductSlug: "runtime", ProductLabel: "Runtime", Cycle: "1", Latest: "1.0.0",
		ReleaseDate: nil, LTSFrom: nil, EOASFrom: nil, EOLFrom: nil, DiscontinuedFrom: nil, IsEOES: nil, EOESFrom: nil, Withdrawn: true,
	}

	firstPage := synccontract.Response{
		SyncedAt: now.Format(time.RFC3339Nano), SyncedXID: 9223372036854775807, FeedStatus: string(domain.ScanFeedStatusHealthy),
		FeedVersions: map[string]string{"osv": now.Format(time.RFC3339Nano)}, Vulnerabilities: []synccontract.Vulnerability{activeVulnerability},
		Malicious: []synccontract.Malicious{activeMalicious}, Reputation: []synccontract.Reputation{activeReputation}, Lifecycle: []synccontract.Lifecycle{activeLifecycle},
		Truncated: true, HasMore: true, NextCursor: &synccontract.Cursor{VulnerabilitiesCursor: "vuln-cursor", MaliciousCursor: "mal-cursor", ReputationCursor: "rep-cursor", LifecycleCursor: "life-cursor"},
	}
	continuationPage := synccontract.Response{
		SyncedAt: firstPage.SyncedAt, SyncedXID: firstPage.SyncedXID, FeedStatus: string(domain.ScanFeedStatusDegraded), FeedVersions: map[string]string{},
		Vulnerabilities: []synccontract.Vulnerability{withdrawnVulnerability}, Malicious: []synccontract.Malicious{withdrawnMalicious},
		Reputation: []synccontract.Reputation{withdrawnReputation}, Lifecycle: []synccontract.Lifecycle{nullLifecycle}, Truncated: true, HasMore: true,
		NextCursor: &synccontract.Cursor{VulnerabilitiesDone: true, MaliciousDone: true, ReputationDone: true, LifecycleCursor: "life-next"},
	}
	finalPage := synccontract.Response{
		SyncedAt: firstPage.SyncedAt, SyncedXID: firstPage.SyncedXID, FeedStatus: string(domain.ScanFeedStatusError), FeedVersions: map[string]string{},
		Vulnerabilities: []synccontract.Vulnerability{}, Malicious: []synccontract.Malicious{}, Reputation: []synccontract.Reputation{}, Lifecycle: []synccontract.Lifecycle{},
		Truncated: false, HasMore: false,
		NextCursor: &synccontract.Cursor{
			VulnerabilitiesDone: true,
			MaliciousDone:       true,
			ReputationDone:      true,
			LifecycleDone:       true,
		},
	}
	for index, page := range []synccontract.Response{firstPage, continuationPage, finalPage} {
		instance := marshalJSONInstance(t, page)
		response := instance.(map[string]any)
		gotXID, ok := response["synced_xid"].(json.Number)
		if !ok || gotXID.String() != "9223372036854775807" {
			t.Fatalf("marshaled synced_xid = %#v, want exact json.Number 9223372036854775807", response["synced_xid"])
		}
		if err := compileOpenAPIFragment(t, compiler, "#/components/schemas/SyncResponse").Validate(instance); err != nil {
			t.Fatalf("canonical SyncResponse does not validate: %v", err)
		}
		if index == 2 {
			cursor := requireMap(t, response, "next_cursor")
			for _, field := range []string{"vulnerabilities_done", "malicious_done", "reputation_done", "lifecycle_done"} {
				if cursor[field] != true {
					t.Fatalf("final SyncCursor.%s = %#v, want true in marshaled wire fixture", field, cursor[field])
				}
			}
		}
	}

	for _, fixture := range []struct {
		schema string
		value  any
	}{
		{schema: "SyncVulnerability", value: activeVulnerability},
		{schema: "SyncVulnerability", value: withdrawnVulnerability},
		{schema: "SyncMalicious", value: activeMalicious},
		{schema: "SyncMalicious", value: withdrawnMalicious},
		{schema: "SyncReputation", value: activeReputation},
		{schema: "SyncReputation", value: withdrawnReputation},
		{schema: "SyncLifecycle", value: activeLifecycle},
		{schema: "SyncLifecycle", value: nullLifecycle},
	} {
		validateMarshaledOpenAPIInstance(t, compiler, "#/components/schemas/"+fixture.schema, fixture.value)
	}
}

func TestOpenAPIMalwareHistoryExampleIsNonBlocking(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	finding := requireMap(t, schemas, "Finding")
	riskType := requireMap(t, requireMap(t, finding, "properties"), "risk_type")
	riskDescription, _ := riskType["description"].(string)
	descriptionDocumentsSemantics := strings.Contains(riskDescription, domain.RiskTypeMalwareHistory) &&
		strings.Contains(riskDescription, "informational") && strings.Contains(riskDescription, "LOW") &&
		(strings.Contains(riskDescription, "never blocks") || strings.Contains(riskDescription, "non-blocking"))

	checkPost := requireMap(t, requireMap(t, requireMap(t, spec, "paths"), "/api/v1/check"), "post")
	examples := requireMap(t, requireMap(t, requireMap(t, requireMap(t, requireMap(t, checkPost, "responses"), "200"), "content"), "application/json"), "examples")
	hasHistoryOnlyNonBlockingExample := false
	for _, raw := range examples {
		example, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		value, ok := example["value"].(map[string]any)
		if !ok || value["findings_blocking"] != false {
			continue
		}
		findings, ok := value["findings"].([]any)
		if !ok || len(findings) == 0 {
			continue
		}
		historyOnly := true
		for _, rawFinding := range findings {
			finding, ok := rawFinding.(map[string]any)
			if !ok || finding["type"] != string(domain.FindingTypeSupplyChainRisk) || finding["risk_type"] != domain.RiskTypeMalwareHistory || finding["severity"] != string(domain.SeverityLow) {
				historyOnly = false
				break
			}
		}
		if historyOnly {
			hasHistoryOnlyNonBlockingExample = true
			break
		}
	}

	violations := make([]string, 0, 2)
	if !descriptionDocumentsSemantics {
		violations = append(violations, "Finding.risk_type malware_history semantics missing")
	}
	if !hasHistoryOnlyNonBlockingExample {
		violations = append(violations, "history-only non-blocking scan example missing")
	}
	wantViolations := []string{
		"Finding.risk_type malware_history semantics missing",
		"history-only non-blocking scan example missing",
	}
	if !reflect.DeepEqual(violations, wantViolations) {
		t.Fatalf("OPEN F010-bugs-5 current violations = %v, want exactly %v; update the bug guard only when the contract changes intentionally", violations, wantViolations)
	}
	t.Skip("OPEN F010-bugs-5: Finding.risk_type omits malware_history informational/LOW/non-blocking semantics and the published scan examples omit a history-only non-blocking result")
}

func TestOpenAPISyncPaginationContract(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	paths := requireMap(t, spec, "paths")
	compiler := newOpenAPIInstanceCompiler(t)
	for _, method := range []string{"get", "head"} {
		operation := requireMap(t, requireMap(t, paths, "/api/v1/sync"), method)
		requireExactSyncParameterFamily(t, operation, "cursor", []string{
			"vulnerabilities_cursor", "malicious_cursor", "reputation_cursor", "lifecycle_cursor",
		})
		requireExactSyncParameterFamily(t, operation, "done", []string{
			"vulnerabilities_done", "malicious_done", "reputation_done", "lifecycle_done",
		})
		requireExactSyncParameterFamily(t, operation, "offset", []string{
			"offset", "vulnerabilities_offset", "malicious_offset", "reputation_offset", "lifecycle_offset",
		})

		for _, name := range []string{"vulnerabilities_cursor", "malicious_cursor", "reputation_cursor", "lifecycle_cursor"} {
			parameter := requireOperationParameter(t, operation, name, "query")
			if got := requireMap(t, parameter, "schema")["type"]; got != "string" {
				t.Fatalf("%s sync %s type = %#v, want string", method, name, got)
			}
			schema := compileOpenAPISyncParameterSchema(t, compiler, operation, method, name)
			requireSchemaInstances(t, schema, method+" sync "+name,
				[]any{"opaque-runtime-cursor"},
				[]any{true, json.Number("1"), []any{}},
			)
		}
		for _, name := range []string{"vulnerabilities_done", "malicious_done", "reputation_done", "lifecycle_done"} {
			parameter := requireOperationParameter(t, operation, name, "query")
			if got := requireMap(t, parameter, "schema")["type"]; got != "boolean" {
				t.Fatalf("%s sync %s type = %#v, want boolean", method, name, got)
			}
			schema := compileOpenAPISyncParameterSchema(t, compiler, operation, method, name)
			requireSchemaInstances(t, schema, method+" sync "+name,
				[]any{true, false},
				[]any{"true", json.Number("1"), nil},
			)
		}
		ecosystem := requireOperationParameter(t, operation, "ecosystem", "query")
		if ecosystem["style"] != "form" || ecosystem["explode"] != false {
			t.Fatalf("%s sync ecosystem serialization = style %#v explode %#v, want form/false", method, ecosystem["style"], ecosystem["explode"])
		}
		ecosystemSchema := requireMap(t, ecosystem, "schema")
		if ecosystemSchema["type"] != "array" || requireMap(t, ecosystemSchema, "items")["$ref"] != "#/components/schemas/Ecosystem" {
			t.Fatalf("%s sync ecosystem schema = %#v, want array of Ecosystem refs", method, ecosystemSchema)
		}
		requireSchemaInstances(t, compileOpenAPISyncParameterSchema(t, compiler, operation, method, "ecosystem"), method+" sync ecosystem",
			[]any{[]any{string(domain.EcosystemNPM)}, []any{string(domain.EcosystemNPM), string(domain.EcosystemGo)}},
			[]any{"npm", []any{"not-an-ecosystem"}, []any{json.Number("1")}},
		)

		limit := requireMap(t, requireOperationParameter(t, operation, "limit", "query"), "schema")
		if requireInt(t, limit, "minimum") != 1 || requireInt(t, limit, "maximum") != synccontract.MaxLimit || requireInt(t, limit, "default") != synccontract.DefaultLimit {
			t.Fatalf("%s sync limit schema = %#v, want min 1 max %d default %d", method, limit, synccontract.MaxLimit, synccontract.DefaultLimit)
		}
		requireSchemaInstances(t, compileOpenAPISyncParameterSchema(t, compiler, operation, method, "limit"), method+" sync limit",
			[]any{json.Number("1"), json.Number("10000")},
			[]any{json.Number("0"), json.Number("10001"), json.Number("1.5"), "1"},
		)
		for _, name := range []string{"offset", "vulnerabilities_offset", "malicious_offset", "reputation_offset", "lifecycle_offset"} {
			parameter := requireOperationParameter(t, operation, name, "query")
			schema := requireMap(t, parameter, "schema")
			if requireInt(t, schema, "minimum") != 0 || requireInt(t, schema, "maximum") != 10000 || parameter["deprecated"] != true {
				t.Fatalf("%s sync %s contract = %#v, want deprecated integer range 0..10000", method, name, parameter)
			}
			requireSchemaInstances(t, compileOpenAPISyncParameterSchema(t, compiler, operation, method, name), method+" sync "+name,
				[]any{json.Number("0"), json.Number("10000")},
				[]any{json.Number("-1"), json.Number("10001"), json.Number("1.5"), "0"},
			)
		}
		for _, name := range []string{"since_xid", "snapshot_xid"} {
			schema := requireMap(t, requireOperationParameter(t, operation, name, "query"), "schema")
			if schema["type"] != "integer" || requireInt(t, schema, "minimum") != 0 || requireInt(t, schema, "maximum") != 9223372036854775807 {
				t.Fatalf("%s sync %s schema = %#v, want exact signed-bigint bounds", method, name, schema)
			}
			requireSchemaInstances(t, compileOpenAPISyncParameterSchema(t, compiler, operation, method, name), method+" sync "+name,
				[]any{json.Number("0"), json.Number("9223372036854775807")},
				[]any{json.Number("-1"), json.Number("9223372036854775808")},
			)
		}
		for _, name := range []string{"since", "snapshot"} {
			parameter := requireOperationParameter(t, operation, name, "query")
			schemaMap := requireMap(t, parameter, "schema")
			if schemaMap["format"] != "date-time" {
				t.Fatalf("%s sync %s format = %#v, want date-time annotation", method, name, schemaMap["format"])
			}
			parameterIndex := operationParameterIndex(t, operation, name, "query")
			fragment := fmt.Sprintf("#/paths/~1api~1v1~1sync/%s/parameters/%d/schema", method, parameterIndex)
			if err := compileOpenAPIFragment(t, compiler, fragment).Validate("not-a-date-time"); err != nil {
				t.Fatalf("%s sync %s format unexpectedly rejects an instance; compiler must keep OpenAPI format annotation-only: %v", method, name, err)
			}
		}
	}
}

func TestOpenAPIEnumsExactlyMatchDomainCapabilities(t *testing.T) {
	spec := readOpenAPISpecMap(t)
	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	allEcosystems := []domain.Ecosystem{
		domain.EcosystemNPM, domain.EcosystemPyPI, domain.EcosystemGo, domain.EcosystemMaven, domain.EcosystemCargo,
		domain.EcosystemNuGet, domain.EcosystemComposer, domain.EcosystemGem, domain.EcosystemPub, domain.EcosystemGitHubActions,
		domain.EcosystemCocoaPods, domain.EcosystemSwiftPM, domain.EcosystemHex, domain.EcosystemCRAN, domain.EcosystemDocker, domain.EcosystemChocolatey,
	}
	wantEcosystems := make([]string, 0, len(allEcosystems))
	wantScanEcosystems := make([]string, 0, len(allEcosystems))
	wantRefreshEcosystems := make([]string, 0, len(allEcosystems))
	for _, ecosystem := range allEcosystems {
		if !ecosystem.Valid() {
			t.Fatalf("canonical ecosystem %q is not valid", ecosystem)
		}
		wantEcosystems = append(wantEcosystems, string(ecosystem))
		if ecosystem.ScanInput() {
			wantScanEcosystems = append(wantScanEcosystems, string(ecosystem))
		}
		if socket.SupportsEcosystem(string(ecosystem)) {
			wantRefreshEcosystems = append(wantRefreshEcosystems, string(ecosystem))
		}
	}
	requireExactStringEnumValues(t, requireMap(t, schemas, "Ecosystem"), "Ecosystem", wantEcosystems)
	requireExactStringEnumValues(t, requireMap(t, schemas, "ScanEcosystem"), "ScanEcosystem", wantScanEcosystems)
	requireExactStringEnumValues(t, requireMap(t, schemas, "RefreshEcosystem"), "RefreshEcosystem", wantRefreshEcosystems)

	scanResultProperties := requireMap(t, requireMap(t, schemas, "ScanResult"), "properties")
	requireExactStringEnumValues(t, requireMap(t, scanResultProperties, "mode"), "ScanResult.mode", scanModeStrings(domain.ScanModeValues()))
	requireExactStringEnumValues(t, requireMap(t, scanResultProperties, "feed_status"), "ScanResult.feed_status", scanFeedStatusStrings(domain.ScanFeedStatusValues()))
	requireExactStringEnumValues(t, requireMap(t, scanResultProperties, "block_threshold"), "ScanResult.block_threshold", []string{
		string(domain.SeverityCritical), string(domain.SeverityHigh), string(domain.SeverityMedium), string(domain.SeverityLow), string(domain.SeverityNone),
	})
	findingProperties := requireMap(t, requireMap(t, schemas, "Finding"), "properties")
	requireExactStringEnumValues(t, requireMap(t, findingProperties, "type"), "Finding.type", []string{
		string(domain.FindingTypeVulnerability), string(domain.FindingTypeMalicious), string(domain.FindingTypeSupplyChainRisk), string(domain.FindingTypeLifecycle),
	})
	requireExactStringEnumValues(t, requireMap(t, findingProperties, "severity"), "Finding.severity", []string{
		string(domain.SeverityCritical), string(domain.SeverityHigh), string(domain.SeverityMedium), string(domain.SeverityLow), string(domain.SeverityUnknown),
	})
	requireExactStringEnumValues(t, requireMap(t, findingProperties, "risk_type"), "Finding.risk_type", []string{
		"malware", "typosquatting", "supply_chain", "removed_package", domain.RiskTypeMalwareHistory, "eol", "eol_soon", "security_support_only", "other",
	})
	requireExactStringEnumValues(t, requireMap(t, requireMap(t, requireMap(t, schemas, "SyncResponse"), "properties"), "feed_status"), "SyncResponse.feed_status", scanFeedStatusStrings(domain.ScanFeedStatusValues()))

	syncProperties := requireMap(t, requireMap(t, schemas, "SyncResponse"), "properties")
	wantRowRefs := map[string]string{
		"vulnerabilities": "#/components/schemas/SyncVulnerability",
		"malicious":       "#/components/schemas/SyncMalicious",
		"reputation":      "#/components/schemas/SyncReputation",
		"lifecycle":       "#/components/schemas/SyncLifecycle",
	}
	for field, wantRef := range wantRowRefs {
		property := requireMap(t, syncProperties, field)
		if property["type"] != "array" || requireMap(t, property, "items")["$ref"] != wantRef {
			t.Fatalf("SyncResponse.%s = %#v, want array items ref %s", field, property, wantRef)
		}
	}
}

func TestOpenAPIDocumentsPackageDetailResponse(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	packageDetail := requireMap(t, paths, "/api/v1/packages/{ecosystem}/{rest}")
	get := requireMap(t, packageDetail, "get")
	parameters, ok := get["parameters"].([]any)
	if !ok {
		t.Fatalf("package detail parameters = %#v, want array", get["parameters"])
	}
	hasVersionQuery := false
	hasRefreshSuffixDocumentation := false
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if parameter["name"] == "version" && parameter["in"] == "query" {
			hasVersionQuery = true
			continue
		}
		if parameter["name"] == "rest" && parameter["in"] == "path" {
			description, _ := parameter["description"].(string)
			hasRefreshSuffixDocumentation = strings.Contains(description, "GET/HEAD package detail requests may address names ending in /refresh") &&
				strings.Contains(description, "only POST reserves a trailing /refresh suffix")
		}
	}
	if !hasVersionQuery {
		t.Fatal("package detail is missing optional version query parameter")
	}
	if !hasRefreshSuffixDocumentation {
		t.Fatal("package detail rest parameter must document the GET/HEAD vs POST /refresh suffix contract")
	}

	responses := requireMap(t, get, "responses")
	for _, method := range []string{"get", "head"} {
		operation := requireMap(t, packageDetail, method)
		notFound := requireMap(t, requireMap(t, operation, "responses"), "404")
		description, _ := notFound["description"].(string)
		for _, want := range []string{"No findings", "package coordinate"} {
			if !strings.Contains(description, want) {
				t.Fatalf("package detail %s 404 description missing %q: %q", method, want, description)
			}
		}
	}

	okResponse := requireMap(t, responses, "200")
	content := requireMap(t, okResponse, "content")
	jsonContent := requireMap(t, content, "application/json")
	schema := requireMap(t, jsonContent, "schema")
	if got := schema["$ref"]; got != "#/components/schemas/PackageDetailResponse" {
		t.Fatalf("package detail 200 schema ref = %#v, want PackageDetailResponse", got)
	}

	schemas := requireMap(t, requireMap(t, spec, "components"), "schemas")
	packageSchema := requireMap(t, schemas, "PackageDetailResponse")
	properties := requireMap(t, packageSchema, "properties")
	findings := requireMap(t, properties, "findings")
	items := requireMap(t, findings, "items")
	if got := items["$ref"]; got != "#/components/schemas/Finding" {
		t.Fatalf("PackageDetailResponse findings item ref = %#v, want Finding", got)
	}
}

func TestOpenAPIDocumentsPackageCatchAllPaths(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path   string
		method string
	}{
		{path: "/api/v1/packages/{ecosystem}/{rest}", method: "get"},
		{path: "/api/v1/packages/{ecosystem}/{rest}/refresh", method: "post"},
	}
	for _, tt := range cases {
		pathItem := requireMap(t, paths, tt.path)
		operation := requireMap(t, pathItem, tt.method)
		parameters, ok := operation["parameters"].([]any)
		if !ok {
			t.Fatalf("%s %s parameters = %#v, want array", tt.method, tt.path, operation["parameters"])
		}
		var rest map[string]any
		for _, raw := range parameters {
			parameter, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if parameter["name"] == "rest" && parameter["in"] == "path" {
				rest = parameter
				break
			}
		}
		if rest == nil {
			t.Fatalf("%s %s missing rest path parameter", tt.method, tt.path)
		}
		if rest["x-packmon-catch-all"] != true {
			t.Fatalf("%s %s rest parameter missing x-packmon-catch-all=true: %#v", tt.method, tt.path, rest)
		}
		if rest["allowReserved"] != true {
			t.Fatalf("%s %s rest parameter missing allowReserved=true: %#v", tt.method, tt.path, rest)
		}
		description, _ := rest["description"].(string)
		for _, want := range []string{"remaining path segments", "@scope/pkg"} {
			if !strings.Contains(description, want) {
				t.Fatalf("%s %s rest description missing %q: %q", tt.method, tt.path, want, description)
			}
		}
		example, _ := rest["example"].(string)
		if !strings.Contains(example, "@scope/pkg") {
			t.Fatalf("%s %s rest example = %q, want scoped package", tt.method, tt.path, example)
		}
	}
}

const openAPIInstanceResourceURL = "https://packmon.test/openapi/packmon-v1.yaml"

func readOpenAPISpecMap(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}
	return spec
}

func newOpenAPIInstanceCompiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(openAPIInstanceResourceURL, document); err != nil {
		t.Fatalf("add whole OpenAPI document as JSON Schema resource: %v", err)
	}
	return compiler
}

func compileOpenAPIFragment(t *testing.T, compiler *jsonschema.Compiler, fragment string) *jsonschema.Schema {
	t.Helper()
	schema, err := compiler.Compile(openAPIInstanceResourceURL + fragment)
	if err != nil {
		t.Fatalf("compile OpenAPI schema fragment %s: %v", fragment, err)
	}
	return schema
}

func decodeJSONInstance(t *testing.T, raw string) any {
	t.Helper()
	var instance any
	if err := json.Unmarshal([]byte(raw), &instance); err != nil {
		t.Fatalf("decode JSON instance: %v", err)
	}
	return instance
}

func marshalJSONInstance(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal canonical JSON instance: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var instance any
	if err := decoder.Decode(&instance); err != nil {
		t.Fatalf("decode canonical JSON instance with exact numbers: %v", err)
	}
	return instance
}

func validateMarshaledOpenAPIInstance(t *testing.T, compiler *jsonschema.Compiler, fragment string, value any) {
	t.Helper()
	instance := marshalJSONInstance(t, value)
	if err := compileOpenAPIFragment(t, compiler, fragment).Validate(instance); err != nil {
		t.Fatalf("canonical payload does not validate against %s: %v", fragment, err)
	}
}

func collectOpenAPIExampleLocations(value any, path string, out map[string]struct{}) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			childPath := key
			if path != "" {
				childPath = path + "/" + key
			}
			switch key {
			case "example":
				out[childPath] = struct{}{}
			case "examples":
				examples, ok := child.(map[string]any)
				if !ok {
					continue
				}
				for name, rawExample := range examples {
					example, ok := rawExample.(map[string]any)
					if !ok {
						continue
					}
					if _, ok := example["value"]; ok {
						out[childPath+"/"+name+"/value"] = struct{}{}
					}
				}
			default:
				collectOpenAPIExampleLocations(child, childPath, out)
			}
		}
	case []any:
		for index, child := range value {
			collectOpenAPIExampleLocations(child, fmt.Sprintf("%s/%d", path, index), out)
		}
	}
}

func operationParameterIndex(t *testing.T, operation map[string]any, name, in string) int {
	t.Helper()
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("operation parameters = %#v, want array", operation["parameters"])
	}
	for index, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if ok && parameter["name"] == name && parameter["in"] == in {
			return index
		}
	}
	t.Fatalf("operation missing %s parameter %q", in, name)
	return -1
}

func compileOpenAPISyncParameterSchema(t *testing.T, compiler *jsonschema.Compiler, operation map[string]any, method, name string) *jsonschema.Schema {
	t.Helper()
	parameterIndex := operationParameterIndex(t, operation, name, "query")
	fragment := fmt.Sprintf("#/paths/~1api~1v1~1sync/%s/parameters/%d/schema", method, parameterIndex)
	return compileOpenAPIFragment(t, compiler, fragment)
}

func requireSchemaInstances(t *testing.T, schema *jsonschema.Schema, name string, accepted, rejected []any) {
	t.Helper()
	for _, instance := range accepted {
		if err := schema.Validate(instance); err != nil {
			t.Errorf("%s rejected valid instance %#v: %v", name, instance, err)
		}
	}
	for _, instance := range rejected {
		if err := schema.Validate(instance); err == nil {
			t.Errorf("%s accepted invalid instance %#v", name, instance)
		}
	}
}

func requireExactSyncParameterFamily(t *testing.T, operation map[string]any, family string, wantNames []string) {
	t.Helper()
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("operation parameters = %#v, want array", operation["parameters"])
	}
	want := make(map[string]struct{}, len(wantNames))
	for _, name := range wantNames {
		want[name] = struct{}{}
	}
	got := make(map[string]struct{}, len(wantNames))
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := parameter["name"].(string)
		matches := false
		switch family {
		case "cursor":
			matches = strings.HasSuffix(name, "_cursor")
		case "done":
			matches = strings.HasSuffix(name, "_done")
		case "offset":
			matches = name == "offset" || strings.HasSuffix(name, "_offset")
		default:
			t.Fatalf("unknown sync parameter family %q", family)
		}
		if !matches {
			continue
		}
		if _, duplicate := got[name]; duplicate {
			t.Fatalf("sync %s parameter %q is duplicated", family, name)
		}
		got[name] = struct{}{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sync %s parameters = %v, want exact duplicate-free set %v", family, got, want)
	}
}

func requireExactStringEnumValues(t *testing.T, schema map[string]any, name string, want []string) {
	t.Helper()
	raw, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("%s enum = %#v, want array", name, schema["enum"])
	}
	if len(raw) != len(want) {
		t.Fatalf("%s enum length = %d (%v), want exact %d values %v", name, len(raw), raw, len(want), want)
	}
	got := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s enum value = %#v, want string", name, value)
		}
		if _, duplicate := got[text]; duplicate {
			t.Fatalf("%s enum contains duplicate %q", name, text)
		}
		got[text] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, value := range want {
		if _, duplicate := wantSet[value]; duplicate {
			t.Fatalf("%s expected capability list contains duplicate %q", name, value)
		}
		wantSet[value] = struct{}{}
	}
	if !reflect.DeepEqual(got, wantSet) {
		t.Fatalf("%s enum = %v, want exact capabilities %v", name, enumKeys(got), enumKeys(wantSet))
	}
}

func scanModeStrings(values []domain.ScanMode) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}

func scanFeedStatusStrings(values []domain.ScanFeedStatus) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}

func runtimeCheckCoordinateAccepted(name, version string) bool {
	if utf8.RuneCountInString(name) > checkcontract.MaxScanPackageNameCodePoints ||
		utf8.RuneCountInString(version) > checkcontract.MaxScanPackageVersionCodePoints {
		return false
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	return name != "" && version != "" &&
		len(strings.Fields(version)) == 1
}

func requireMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key]
	if !ok {
		t.Fatalf("missing key %q in %#v", key, parent)
	}
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("key %q = %#v, want map", key, value)
	}
	return out
}

func requireStringEnum(t *testing.T, schema map[string]any, name string) map[string]struct{} {
	t.Helper()
	enumValues, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("%s enum = %#v, want array", name, schema["enum"])
	}
	out := make(map[string]struct{}, len(enumValues))
	for _, value := range enumValues {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s enum value = %#v, want string", name, value)
		}
		out[text] = struct{}{}
	}
	return out
}

func requireOperationParameter(t *testing.T, operation map[string]any, name, in string) map[string]any {
	t.Helper()
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("operation parameters = %#v, want array", operation["parameters"])
	}
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if parameter["name"] == name && parameter["in"] == in {
			return parameter
		}
	}
	t.Fatalf("operation missing %s parameter %q", in, name)
	return nil
}

func operationHasParameterRef(operation map[string]any, ref string) bool {
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		return false
	}
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if parameter["$ref"] == ref {
			return true
		}
	}
	return false
}

func requireResponseHeaderRef(t *testing.T, response map[string]any, name, ref string) map[string]any {
	t.Helper()
	headers := requireMap(t, response, "headers")
	header := requireMap(t, headers, name)
	if got := header["$ref"]; got != ref {
		t.Fatalf("response header %s ref = %#v, want %s", name, got, ref)
	}
	return header
}

func requireRequiredFields(t *testing.T, schema map[string]any, schemaName string, fields ...string) {
	t.Helper()
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("%s required = %#v, want array", schemaName, schema["required"])
	}
	seen := make(map[string]struct{}, len(required))
	for _, value := range required {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s required value = %#v, want string", schemaName, value)
		}
		seen[text] = struct{}{}
	}
	for _, field := range fields {
		if _, ok := seen[field]; !ok {
			t.Fatalf("%s required fields missing %q; got %v", schemaName, field, enumKeys(seen))
		}
	}
}

func requireInt(t *testing.T, schema map[string]any, key string) int {
	t.Helper()
	value, ok := schema[key]
	if !ok {
		t.Fatalf("missing integer key %q in %#v", key, schema)
	}
	out, ok := value.(int)
	if !ok {
		t.Fatalf("key %q = %#v, want int", key, value)
	}
	return out
}

func requireBool(t *testing.T, schema map[string]any, key string) bool {
	t.Helper()
	value, ok := schema[key]
	if !ok {
		t.Fatalf("missing boolean key %q in %#v", key, schema)
	}
	out, ok := value.(bool)
	if !ok {
		t.Fatalf("key %q = %#v, want bool", key, value)
	}
	return out
}

func enumKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return keys
}

func validateOpenAPI32Document(data []byte) error {
	document, err := libopenapi.NewDocument(data)
	if err != nil {
		return fmt.Errorf("parse OpenAPI document: %w", err)
	}
	if got := document.GetVersion(); got != "3.2.0" {
		return fmt.Errorf("OpenAPI version = %s, want 3.2.0", got)
	}
	if got := document.GetSpecInfo().SpecFormat; got != datamodel.OAS32 {
		return fmt.Errorf("OpenAPI spec format = %s, want %s", got, datamodel.OAS32)
	}
	if _, err := document.BuildV3Model(); err != nil {
		return fmt.Errorf("build OpenAPI 3.2 model: %w", err)
	}

	var openAPISchema any
	if err := yaml.Unmarshal([]byte(datamodel.OpenAPI32SchemaData), &openAPISchema); err != nil {
		return fmt.Errorf("parse embedded OpenAPI 3.2 schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://spec.openapis.org/oas/3.2/schema/2025-09-17", openAPISchema); err != nil {
		return fmt.Errorf("add embedded OpenAPI 3.2 schema: %w", err)
	}
	schema, err := compiler.Compile("https://spec.openapis.org/oas/3.2/schema/2025-09-17")
	if err != nil {
		return fmt.Errorf("compile embedded OpenAPI 3.2 schema: %w", err)
	}

	var spec any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("parse OpenAPI YAML for schema validation: %w", err)
	}
	if err := schema.Validate(spec); err != nil {
		return fmt.Errorf("validate against OpenAPI 3.2 schema: %w", err)
	}
	return nil
}
