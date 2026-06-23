package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestAPIKeyMutationHandlersShareAuthFormAndAuditFlow(t *testing.T) {
	t.Parallel()

	funcs := parseAdminPagesFunctions(t)
	helper := funcs["handleAPIKeyMutation"]
	if helper == nil {
		t.Fatal("pages.go missing shared handleAPIKeyMutation helper")
	}

	for _, name := range []string{"HandleKeyRevoke", "HandleKeyDelete"} {
		fn := funcs[name]
		if fn == nil {
			t.Fatalf("pages.go missing %s", name)
		}
		calls := functionCallNames(fn)
		if !calls["handleAPIKeyMutation"] {
			t.Fatalf("%s does not delegate to handleAPIKeyMutation", name)
		}
		for _, forbidden := range []string{
			"requireAdmin",
			"parseAdminForm",
			"ValidateCSRF",
			"requireBootstrapPasswordRotated",
			"apiKeyAuditDetails",
			"writeAdminAuditLog",
		} {
			if calls[forbidden] {
				t.Fatalf("%s still contains shared admin mutation flow call %s", name, forbidden)
			}
		}
	}

	helperCalls := functionCallNames(helper)
	for _, want := range []string{
		"requireAdmin",
		"parseAdminForm",
		"ValidateCSRF",
		"requireBootstrapPasswordRotated",
		"apiKeyAuditDetails",
		"writeAdminAuditLog",
		"adminMutationErrorMessage",
	} {
		if !helperCalls[want] {
			t.Fatalf("handleAPIKeyMutation missing shared flow call %s", want)
		}
	}
}

func parseAdminPagesFunctions(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()

	src, err := os.ReadFile("pages.go")
	if err != nil {
		t.Fatalf("read pages.go: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "pages.go", src, 0)
	if err != nil {
		t.Fatalf("parse pages.go: %v", err)
	}
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		funcs[fn.Name.Name] = fn
	}
	return funcs
}

func functionCallNames(fn *ast.FuncDecl) map[string]bool {
	calls := make(map[string]bool)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, name := range callExpressionNames(call.Fun) {
			calls[name] = true
		}
		return true
	})
	return calls
}

func callExpressionNames(expr ast.Expr) []string {
	switch fun := expr.(type) {
	case *ast.Ident:
		return []string{fun.Name}
	case *ast.SelectorExpr:
		names := callExpressionNames(fun.X)
		names = append(names, fun.Sel.Name)
		if len(names) >= 2 {
			names = append(names, strings.Join(names[len(names)-2:], "."))
		}
		return names
	default:
		return nil
	}
}
