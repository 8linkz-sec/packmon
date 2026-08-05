package ci

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	apiv1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/synccontract"
	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/datamodel"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

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

	limit := requireOperationParameter(t, syncOperation, "limit", "query")
	limitSchema := requireMap(t, limit, "schema")
	if got := requireInt(t, limitSchema, "default"); got != synccontract.DefaultLimit {
		t.Fatalf("/api/v1/sync limit default = %d, want %d", got, synccontract.DefaultLimit)
	}
	if got := requireInt(t, limitSchema, "maximum"); got != synccontract.MaxLimit {
		t.Fatalf("/api/v1/sync limit maximum = %d, want %d", got, synccontract.MaxLimit)
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
	if _, ok := scanEcosystemEnums[string(domain.EcosystemDocker)]; ok {
		t.Fatalf("ScanEcosystem must not include %q", domain.EcosystemDocker)
	}

	name := requireMap(t, scanProperties, "name")
	if got := requireInt(t, name, "minLength"); got != 1 {
		t.Fatalf("ScanPackage.name minLength = %d, want 1", got)
	}
	if got := requireInt(t, name, "maxLength"); got != checkcontract.MaxPackageNameLength {
		t.Fatalf("ScanPackage.name maxLength = %d, want %d", got, checkcontract.MaxPackageNameLength)
	}
	if got := name["pattern"]; got != `.*\S.*` {
		t.Fatalf("ScanPackage.name pattern = %#v, want non-blank pattern", got)
	}
	version := requireMap(t, scanProperties, "version")
	if got := requireInt(t, version, "minLength"); got != 1 {
		t.Fatalf("ScanPackage.version minLength = %d, want 1", got)
	}
	if got := requireInt(t, version, "maxLength"); got != checkcontract.MaxPackageVersionLength {
		t.Fatalf("ScanPackage.version maxLength = %d, want %d", got, checkcontract.MaxPackageVersionLength)
	}
	if got := version["pattern"]; got != `^\s*\S+\s*$` {
		t.Fatalf("ScanPackage.version pattern = %#v, want single-token version pattern", got)
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
		{"/api/v1/check", "post", []string{"400", "401", "403", "409", "429", "503", "500"}},
		{"/api/v1/feeds/status", "get", []string{"401", "403", "429", "500"}},
		{"/api/v1/feeds/{feed}/import", "post", []string{"400", "401", "403", "404", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}", "get", []string{"400", "401", "403", "404", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}/refresh", "post", []string{"400", "401", "403", "409", "429", "500"}},
		{"/api/v1/sync", "get", []string{"400", "401", "403", "429", "500"}},
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
	for _, unsupported := range []string{"actions", "docker", "pub", "cocoapods", "swiftpm", "hex", "cran"} {
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
	for _, want := range []string{
		"osv and ghsa use VulnerabilityImportRequest",
		"openssf, malicious, and socket use MaliciousImportRequest",
		"vulncheck uses VulnCheckImportRequest",
		"cisakev uses CISAKEVImportRequest",
		"epss uses EPSSImportRequest",
	} {
		if !strings.Contains(operationDescription, want) {
			t.Fatalf("feed import operation description missing feed-to-schema guidance %q: %q", want, operationDescription)
		}
	}
	requestBody := requireMap(t, post, "requestBody")
	requestBodyDescription, _ := requestBody["description"].(string)
	for _, want := range []string{
		"osv/ghsa",
		"openssf/malicious/socket",
		"vulncheck",
		"cisakev",
		"epss",
	} {
		if !strings.Contains(requestBodyDescription, want) {
			t.Fatalf("feed import request body description missing %q mapping: %q", want, requestBodyDescription)
		}
	}
	requestContent := requireMap(t, requireMap(t, requestBody, "content"), "application/json")
	requestSchema := requireMap(t, requestContent, "schema")
	anyOf, ok := requestSchema["anyOf"].([]any)
	if !ok || len(anyOf) < 5 {
		t.Fatalf("feed import request schema anyOf = %#v, want path-dispatched feed request refs", requestSchema["anyOf"])
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
