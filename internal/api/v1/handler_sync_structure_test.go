package v1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestHandleSyncDelegatesFocusedResponsibilities(t *testing.T) {
	t.Parallel()

	body := functionBodySource(t, "sync.go", "HandleSync")
	for _, want := range []string{
		"parseSyncRequest(",
		"exportSyncData(",
		"syncResponseEnvelope(",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleSync body does not delegate to %s:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"parseSyncExportOptions(",
		".ExportSync(",
		".feedState(",
		"syncResponseFromExport(",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("HandleSync body contains lower-level sync responsibility %s:\n%s", forbidden, body)
		}
	}
}

func TestHandleSyncUsesStreamingJSONForOKPages(t *testing.T) {
	t.Parallel()

	body := functionBodySource(t, "sync.go", "HandleSync")
	if !strings.Contains(body, "writeStreamingJSONForRequest(w, r, http.StatusOK, resp)") {
		t.Fatalf("HandleSync OK response does not use streaming JSON writer:\n%s", body)
	}
	if strings.Contains(body, "writeJSONForRequest(w, r, http.StatusOK, resp)") {
		t.Fatalf("HandleSync OK response still uses buffering JSON writer:\n%s", body)
	}
}

func TestStreamingJSONHelperEncodesDirectlyToResponseWriter(t *testing.T) {
	t.Parallel()

	body := functionBodySource(t, "handler.go", "writeStreamingJSONForRequest")
	if !strings.Contains(body, "json.NewEncoder(w)") {
		t.Fatalf("writeStreamingJSONForRequest does not encode directly to ResponseWriter:\n%s", body)
	}
	if strings.Contains(body, "encodeJSONResponse(") || strings.Contains(body, "bytes.Buffer") {
		t.Fatalf("writeStreamingJSONForRequest still buffers JSON before writing:\n%s", body)
	}
}

func TestSyncResponseFromExportDelegatesDatasetMapping(t *testing.T) {
	t.Parallel()

	body := functionBodySource(t, "sync.go", "syncResponseFromExport")
	for _, want := range []string{
		"newSyncResponseEnvelope(",
		"syncVulnerabilityResponses(",
		"syncMaliciousResponses(",
		"syncReputationResponses(",
		"syncLifecycleResponses(",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("syncResponseFromExport body does not delegate to %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "synccontract.ResponseFromExport(") {
		t.Fatalf("syncResponseFromExport delegates the whole response at once instead of using dataset-specific mappers:\n%s", body)
	}
}

func functionBodySource(t *testing.T, path, name string) string {
	t.Helper()

	//nolint:gosec // G304: path built by the test itself, not from request data.
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("function %s not found in %s", name, path)
	return ""
}
