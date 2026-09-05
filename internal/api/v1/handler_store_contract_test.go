package v1

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type scanLogIdempotencyStoreRequirement interface {
	GetScanLogByIdempotencyKey(context.Context, string) (*db.ScanLogEntry, error)
}

var _ scanLogIdempotencyStoreRequirement = Store(nil)

func TestStoreRequiresScanLogIdempotencyLookup(t *testing.T) {
	t.Parallel()

	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	method, ok := storeType.MethodByName("GetScanLogByIdempotencyKey")
	if !ok {
		t.Fatal("Store does not require GetScanLogByIdempotencyKey")
	}
	if got, want := method.Type.NumIn(), 2; got != want {
		t.Fatalf("GetScanLogByIdempotencyKey inputs = %d, want %d", got, want)
	}
	if method.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("GetScanLogByIdempotencyKey first input = %v, want context.Context", method.Type.In(0))
	}
	if method.Type.In(1).Kind() != reflect.String {
		t.Fatalf("GetScanLogByIdempotencyKey second input = %v, want string", method.Type.In(1))
	}
	if got, want := method.Type.NumOut(), 2; got != want {
		t.Fatalf("GetScanLogByIdempotencyKey outputs = %d, want %d", got, want)
	}
	if method.Type.Out(0) != reflect.TypeOf((*db.ScanLogEntry)(nil)) {
		t.Fatalf("GetScanLogByIdempotencyKey first output = %v, want *db.ScanLogEntry", method.Type.Out(0))
	}
	if method.Type.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("GetScanLogByIdempotencyKey second output = %v, want error", method.Type.Out(1))
	}
}

func TestExistingIdempotentScanUsesRequiredStoreLookup(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate current test file")
	}
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filepath.Join(filepath.Dir(currentFile), "handler.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse handler.go: %v", err)
	}
	fn := findFunction(file, "existingIdempotentScan")
	if fn == nil {
		t.Fatal("existingIdempotentScan not found")
	}

	var hasLookupCall bool
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch expr := node.(type) {
		case *ast.TypeAssertExpr:
			t.Fatalf("existingIdempotentScan uses type assertion at %s; Store should require idempotency lookup", fileSet.Position(expr.Pos()))
		case *ast.SelectorExpr:
			if expr.Sel.Name == "GetScanLogByIdempotencyKey" && isHandlerStoreSelector(expr.X) {
				hasLookupCall = true
			}
		}
		return true
	})
	if !hasLookupCall {
		t.Fatal("existingIdempotentScan does not call h.store.GetScanLogByIdempotencyKey")
	}
}

func findFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func isHandlerStoreSelector(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "store" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && receiver.Name == "h"
}
