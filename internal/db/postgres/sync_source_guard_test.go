package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestExportSyncLifecycleDelegatesQueryExecutionAndMapping(t *testing.T) {
	t.Parallel()

	source := postgresFunctionSource(t, "sync.go", "exportSyncLifecycle")
	for _, want := range []string{
		"buildExportSyncLifecycleQuery(",
		"querySyncLifecycleRows(",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("exportSyncLifecycle missing delegated helper call %q", want)
		}
	}
	for _, forbidden := range []string{
		"s.pool.Query(",
		"rows.Next(",
		".Scan(",
		"strings.Join(",
		"fmt.Sprintf(",
		"lifecycle_package_map",
		"lifecycle_sync_tombstones",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("exportSyncLifecycle must delegate SQL construction/execution/mapping; found %q in:\n%s", forbidden, source)
		}
	}
}

func postgresFunctionSource(t *testing.T, path, name string) string {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	fileset := token.NewFileSet()
	file, err := parser.ParseFile(fileset, path, source, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		start := fileset.Position(fn.Pos()).Offset
		end := fileset.Position(fn.End()).Offset
		return string(source[start:end])
	}
	t.Fatalf("function %s not found in %s", name, path)
	return ""
}
