package ci

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"gopkg.in/yaml.v3"
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
	}

	importOperation := requireMap(t, requireMap(t, paths, "/api/v1/feeds/{feed}/import"), "post")
	feedParameter := requireOperationParameter(t, importOperation, "feed", "path")
	feedSchema := requireMap(t, feedParameter, "schema")
	feedEnums := requireStringEnum(t, feedSchema, "feed import path parameter")
	for _, want := range []string{"osv", "ghsa", "openssf", "malicious", "vulncheck", "cisakev", "epss", "socket"} {
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
	nextCursor := requireMap(t, syncResponseProperties, "next_cursor")
	if got := nextCursor["$ref"]; got != "#/components/schemas/SyncCursor" {
		t.Fatalf("SyncResponse.next_cursor ref = %#v, want SyncCursor", got)
	}

	syncCursorProperties := requireMap(t, requireMap(t, schemas, "SyncCursor"), "properties")
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
	for _, want := range []string{"remote", "local", "auto"} {
		if _, ok := modeEnums[want]; !ok {
			t.Errorf("ScanResult.mode enum missing %q; got %v", want, enumKeys(modeEnums))
		}
	}

	feedStatus := requireMap(t, properties, "feed_status")
	statusEnums := requireStringEnum(t, feedStatus, "ScanResult.feed_status")
	for _, want := range []string{"healthy", "degraded", "error"} {
		if _, ok := statusEnums[want]; !ok {
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
	if got := requireInt(t, packages, "maxItems"); got != 5000 {
		t.Fatalf("ScanRequest.packages maxItems = %d, want 5000", got)
	}
	packageItems := requireMap(t, packages, "items")
	if got := packageItems["$ref"]; got != "#/components/schemas/ScanPackage" {
		t.Fatalf("ScanRequest.packages item ref = %#v, want ScanPackage", got)
	}

	scanPackage := requireMap(t, schemas, "ScanPackage")
	allOf, ok := scanPackage["allOf"].([]any)
	if !ok || len(allOf) != 2 {
		t.Fatalf("ScanPackage.allOf = %#v, want Package plus ScanEcosystem override", scanPackage["allOf"])
	}
	basePackage, ok := allOf[0].(map[string]any)
	if !ok {
		t.Fatalf("ScanPackage.allOf[0] = %#v, want map", allOf[0])
	}
	if got := basePackage["$ref"]; got != "#/components/schemas/Package" {
		t.Fatalf("ScanPackage base ref = %#v, want Package", got)
	}
	scanOverride, ok := allOf[1].(map[string]any)
	if !ok {
		t.Fatalf("ScanPackage.allOf[1] = %#v, want map", allOf[1])
	}
	scanProperties := requireMap(t, scanOverride, "properties")
	scanEcosystemProperty := requireMap(t, scanProperties, "ecosystem")
	if got := scanEcosystemProperty["$ref"]; got != "#/components/schemas/ScanEcosystem" {
		t.Fatalf("ScanPackage.ecosystem ref = %#v, want ScanEcosystem", got)
	}
	scanEcosystem := requireMap(t, schemas, "ScanEcosystem")
	scanEcosystemEnums := requireStringEnum(t, scanEcosystem, "ScanEcosystem")
	if _, ok := scanEcosystemEnums[string(domain.EcosystemDocker)]; ok {
		t.Fatalf("ScanEcosystem must not include %q", domain.EcosystemDocker)
	}

	packageSchema := requireMap(t, schemas, "Package")
	if got := requireBool(t, packageSchema, "additionalProperties"); got {
		t.Fatalf("Package.additionalProperties = %t, want false to match strict JSON decoding", got)
	}
	requireRequiredFields(t, packageSchema, "Package", "name", "version", "ecosystem")
	packageProperties := requireMap(t, packageSchema, "properties")
	name := requireMap(t, packageProperties, "name")
	if got := requireInt(t, name, "minLength"); got != 1 {
		t.Fatalf("Package.name minLength = %d, want 1", got)
	}
	if got := requireInt(t, name, "maxLength"); got != 512 {
		t.Fatalf("Package.name maxLength = %d, want 512", got)
	}
	if got := name["pattern"]; got != `.*\S.*` {
		t.Fatalf("Package.name pattern = %#v, want non-blank pattern", got)
	}
	version := requireMap(t, packageProperties, "version")
	if got := requireInt(t, version, "minLength"); got != 1 {
		t.Fatalf("Package.version minLength = %d, want 1", got)
	}
	if got := requireInt(t, version, "maxLength"); got != 256 {
		t.Fatalf("Package.version maxLength = %d, want 256", got)
	}
	if got := version["pattern"]; got != `^\s*\S+\s*$` {
		t.Fatalf("Package.version pattern = %#v, want single-token version pattern", got)
	}

	for _, field := range []string{"dev", "direct", "indirect", "optional", "peer"} {
		property := requireMap(t, packageProperties, field)
		if got := property["type"]; got != "boolean" {
			t.Fatalf("Package.%s type = %#v, want boolean", field, got)
		}
	}
	via := requireMap(t, packageProperties, "via")
	if got := via["type"]; got != "array" {
		t.Fatalf("Package.via type = %#v, want array", got)
	}
	viaItems := requireMap(t, via, "items")
	if got := viaItems["type"]; got != "string" {
		t.Fatalf("Package.via item type = %#v, want string", got)
	}
	parents := requireMap(t, packageProperties, "parents")
	if got := parents["type"]; got != "array" {
		t.Fatalf("Package.parents type = %#v, want array", got)
	}
	parentItems := requireMap(t, parents, "items")
	if got := parentItems["$ref"]; got != "#/components/schemas/PackageParent" {
		t.Fatalf("Package.parents item ref = %#v, want PackageParent", got)
	}

	packageParent := requireMap(t, schemas, "PackageParent")
	if got := requireBool(t, packageParent, "additionalProperties"); got {
		t.Fatalf("PackageParent.additionalProperties = %t, want false to match strict JSON decoding", got)
	}
	parentProperties := requireMap(t, packageParent, "properties")
	for _, field := range []string{"name", "version"} {
		property := requireMap(t, parentProperties, field)
		if got := property["type"]; got != "string" {
			t.Fatalf("PackageParent.%s type = %#v, want string", field, got)
		}
	}
	parentEcosystem := requireMap(t, parentProperties, "ecosystem")
	if got := parentEcosystem["$ref"]; got != "#/components/schemas/Ecosystem" {
		t.Fatalf("PackageParent.ecosystem ref = %#v, want Ecosystem", got)
	}

	repoInfo := requireMap(t, schemas, "RepoInfo")
	if got := requireBool(t, repoInfo, "additionalProperties"); got {
		t.Fatalf("RepoInfo.additionalProperties = %t, want false to match strict JSON decoding", got)
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
	requireRequiredFields(t, errorResponse, "ErrorResponse", "error")
	errorProperties := requireMap(t, errorResponse, "properties")
	errorField := requireMap(t, errorProperties, "error")
	if got := errorField["type"]; got != "string" {
		t.Fatalf("ErrorResponse.error type = %#v, want string", got)
	}

	paths := requireMap(t, spec, "paths")
	cases := []struct {
		path     string
		method   string
		statuses []string
	}{
		{"/api/v1/check", "post", []string{"400", "401", "403", "409", "429", "500"}},
		{"/api/v1/feeds/status", "get", []string{"401", "403", "429", "500"}},
		{"/api/v1/feeds/{feed}/import", "post", []string{"400", "401", "403", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}", "get", []string{"400", "401", "403", "404", "429", "500"}},
		{"/api/v1/packages/{ecosystem}/{rest}/refresh", "post", []string{"400", "401", "403", "409", "429", "500"}},
		{"/api/v1/sync", "get", []string{"400", "401", "403", "429", "500", "501"}},
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
		{"/api/v1/sync", []string{"200", "400", "401", "403", "429", "500", "501"}},
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
	result := requireMap(t, properties, "result")
	if got := result["$ref"]; got != "#/components/schemas/ScanResult" {
		t.Fatalf("WebhookEnvelope.result ref = %#v, want ScanResult", got)
	}
	event := requireMap(t, properties, "event")
	eventEnums := requireStringEnum(t, event, "WebhookEnvelope.event")
	if _, ok := eventEnums["scan_completed"]; !ok {
		t.Fatalf("WebhookEnvelope.event enum missing scan_completed; got %v", enumKeys(eventEnums))
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
	requestBody := requireMap(t, post, "requestBody")
	requestContent := requireMap(t, requireMap(t, requestBody, "content"), "application/json")
	requestSchema := requireMap(t, requestContent, "schema")
	oneOf, ok := requestSchema["oneOf"].([]any)
	if !ok || len(oneOf) < 5 {
		t.Fatalf("feed import request schema oneOf = %#v, want feed-specific request refs", requestSchema["oneOf"])
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
	maliciousProps := requireMap(t, maliciousImport, "properties")
	versions := requireMap(t, maliciousProps, "versions")
	if versions["type"] != "array" {
		t.Fatalf("MaliciousImport.versions type = %#v, want array", versions["type"])
	}
	versionItems := requireMap(t, versions, "items")
	if versionItems["type"] != "string" {
		t.Fatalf("MaliciousImport.versions items type = %#v, want string", versionItems["type"])
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
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if parameter["name"] == "version" && parameter["in"] == "query" {
			hasVersionQuery = true
			break
		}
	}
	if !hasVersionQuery {
		t.Fatal("package detail is missing optional version query parameter")
	}

	responses := requireMap(t, get, "responses")
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
