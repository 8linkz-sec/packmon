package feed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFeedSyncUserAgentLiteralIsCentralized(t *testing.T) {
	const userAgent = "packmon-feedsync/1.0"

	var matches []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || value != userAgent {
				return true
			}
			pos := fset.Position(lit.Pos())
			matches = append(matches, filepath.ToSlash(pos.Filename)+":"+strconv.Itoa(pos.Line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan feed source: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("feed sync User-Agent literal should be centralized once, found %d: %v", len(matches), matches)
	}
}
