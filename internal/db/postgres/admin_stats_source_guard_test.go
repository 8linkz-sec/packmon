package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// TestAdminStatsSourceRemainsDeclarationFree keeps admin_stats.go as a
// responsibility-boundary marker. Any import or declaration placed there
// would bypass the file-specific ownership tests that protect the split files.
func TestAdminStatsSourceRemainsDeclarationFree(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "admin_stats.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse admin_stats.go: %v", err)
	}
	if len(file.Imports) != 0 {
		t.Fatalf("admin_stats.go imports = %d, want none", len(file.Imports))
	}
	if len(file.Decls) != 0 {
		t.Fatalf("admin_stats.go declarations = %d, want none", len(file.Decls))
	}
}

func storeMethodsInSourceFile(t *testing.T, filename string) map[string]bool {
	t.Helper()

	//nolint:gosec // G304: path built by the test itself, not from request data.
	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	methods := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		if isStoreReceiver(fn.Recv.List[0].Type) {
			methods[fn.Name.Name] = true
		}
	}
	return methods
}

func isStoreReceiver(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == "Store"
	case *ast.StarExpr:
		ident, ok := typed.X.(*ast.Ident)
		return ok && ident.Name == "Store"
	default:
		return false
	}
}
