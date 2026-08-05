package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRegisterRoutesUsesNamedDependencies(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "routes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse routes.go: %v", err)
	}

	var registerRoutes *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "registerRoutes" {
			registerRoutes = fn
			break
		}
	}
	if registerRoutes == nil {
		t.Fatal("registerRoutes function not found")
	}

	params := registerRoutes.Type.Params.List
	if got := positionalParamCount(params); got != 1 {
		t.Fatalf("registerRoutes accepts %d positional parameters, want one routeDependencies parameter", got)
	}
	paramType, ok := params[0].Type.(*ast.Ident)
	if !ok || paramType.Name != "routeDependencies" {
		t.Fatalf("registerRoutes parameter type = %T, want routeDependencies", params[0].Type)
	}
}

func positionalParamCount(params []*ast.Field) int {
	count := 0
	for _, param := range params {
		if len(param.Names) == 0 {
			count++
			continue
		}
		count += len(param.Names)
	}
	return count
}
