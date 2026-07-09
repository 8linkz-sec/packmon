package scanner

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunWithCollectionPipelineStaysDecomposed(t *testing.T) {
	t.Parallel()

	body := scannerFunctionBodySource(t, "RunWithCollection")

	requiredCalls := []string{
		"s.collectScanPackages(",
		"s.applyParseErrorPolicy(",
		"s.logCollectedPackages(",
		"s.selectAndRunChecker(",
		"s.buildSuccessfulScanResult(",
		"scanExitCode(",
	}
	lastIndex := -1
	for _, call := range requiredCalls {
		index := strings.Index(body, call)
		if index < 0 {
			t.Fatalf("RunWithCollection missing pipeline helper %s:\n%s", call, body)
		}
		if index < lastIndex {
			t.Fatalf("RunWithCollection calls %s out of pipeline order:\n%s", call, body)
		}
		lastIndex = index
	}

	forbiddenInlineWork := []string{
		"CollectPackages(",
		"scanCheckPackages(",
		"FatalParseErrors",
		"checkRemoteResult(",
		"checkLocal(",
		"executeAutoCheckMode(",
		"sortScanFindings(",
		"domain.BuildScanSummary(",
		"hasBlockingFindings(",
	}
	for _, forbidden := range forbiddenInlineWork {
		if strings.Contains(body, forbidden) {
			t.Fatalf("RunWithCollection inlines pipeline work %s:\n%s", forbidden, body)
		}
	}
}

func scannerFunctionBodySource(t *testing.T, name string) string {
	t.Helper()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate scanner pipeline test file")
	}
	scannerPath := filepath.Join(filepath.Dir(testFile), "scanner.go")
	src, err := os.ReadFile(scannerPath)
	if err != nil {
		t.Fatalf("read scanner.go: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, scannerPath, src, 0)
	if err != nil {
		t.Fatalf("parse scanner.go: %v", err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		var body bytes.Buffer
		if err := printer.Fprint(&body, fset, fn.Body); err != nil {
			t.Fatalf("print %s body: %v", name, err)
		}
		return body.String()
	}

	t.Fatalf("function %s not found in scanner.go", name)
	return ""
}
