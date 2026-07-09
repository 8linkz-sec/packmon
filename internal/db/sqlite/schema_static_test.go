package sqlite

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func TestStoreGoDoesNotDeclareSchemaMigrationHelpers(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}

	storePath := filepath.Join(filepath.Dir(currentFile), "store.go")
	file, err := parser.ParseFile(token.NewFileSet(), storePath, nil, 0)
	if err != nil {
		t.Fatalf("parse store.go: %v", err)
	}

	disallowed := map[string]struct{}{
		"ensureMaliciousLocalColumns":                  {},
		"ensureScanHistorySchema":                      {},
		"ensureVulnerabilityLocalColumns":              {},
		"migrateSchema":                                {},
		"migrateVulnerabilityRowKeys":                  {},
		"normalizeExistingCaseInsensitivePackageNames": {},
		"normalizeExistingNamedRows":                   {},
		"normalizeExistingVulnerabilityPackageNames":   {},
		"tableExists":                                  {},
		"tableHasColumn":                               {},
	}
	var found []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		if _, ok := disallowed[fn.Name.Name]; ok {
			found = append(found, fn.Name.Name)
		}
	}
	if len(found) > 0 {
		sort.Strings(found)
		t.Fatalf("store.go declares schema migration helpers %v; keep them in schema.go or migrations.go", found)
	}
}
