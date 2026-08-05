package ci

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthPackageDoesNotExposeFieldEncryptorCompatibilityShim(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	authRoot := filepath.Join(root, "internal", "auth")
	err := filepath.WalkDir(authRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Name.Name == "NewFieldEncryptor" {
					t.Fatalf("%s exposes auth.NewFieldEncryptor; use internal/secret directly", rel)
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.Name == "FieldEncryptor" {
							t.Fatalf("%s exposes auth.FieldEncryptor; use internal/secret directly", rel)
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.Name == "encryptedPrefix" || name.Name == "EncryptedPrefix" {
								t.Fatalf("%s exposes field-encryption prefix compatibility; use internal/secret directly", rel)
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk auth source: %v", err)
	}
}
