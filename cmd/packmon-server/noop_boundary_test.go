package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandPackageDoesNotImplementNoopStore(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(cmd/packmon-server) error = %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					spec, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if spec.Name.Name == "noopStore" || spec.Name.Name == "noopPinger" {
						t.Fatalf("%s declares %s; move development noop implementations out of cmd/packmon-server", name, spec.Name.Name)
					}
				}
			case *ast.FuncDecl:
				if decl.Name.Name == "newNoopStore" {
					t.Fatalf("%s declares newNoopStore; command package should only wire a devstore factory", name)
				}
			}
		}
	}
}

func TestDevstoreNoopPackageSearchUsesFocusedCollectors(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "internal", "devstore", "noop_scan_logs.go"))
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("ParseFile(%s) error = %v", path, err)
	}

	requiredFuncs := map[string]bool{
		"collectNoopVulnerabilitySearch":   false,
		"collectNoopMaliciousSearch":       false,
		"finalizeNoopPackageSearchResults": false,
	}
	requiredSearchCalls := map[string]bool{
		"collectNoopVulnerabilitySearch":   false,
		"collectNoopMaliciousSearch":       false,
		"finalizeNoopPackageSearchResults": false,
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := requiredFuncs[fn.Name.Name]; ok {
			requiredFuncs[fn.Name.Name] = true
		}
		if fn.Name.Name != "SearchPackages" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if _, ok := requiredSearchCalls[name.Name]; ok {
				requiredSearchCalls[name.Name] = true
			}
			return true
		})
	}

	for name, found := range requiredFuncs {
		if !found {
			t.Fatalf("%s missing from devstore noop package search", name)
		}
	}
	for name, found := range requiredSearchCalls {
		if !found {
			t.Fatalf("SearchPackages does not call %s", name)
		}
	}
}
