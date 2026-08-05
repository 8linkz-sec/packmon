package ci

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryPinsGoSourceLineEndingsToLF(t *testing.T) {
	root := filepath.Join("..", "..")
	attrsPath := filepath.Join(root, ".gitattributes")
	attrs, err := os.ReadFile(attrsPath) // #nosec G304 -- test reads a fixed repository fixture path.
	if err != nil {
		t.Fatalf("read .gitattributes: %v", err)
	}
	if !strings.Contains(string(attrs), "*.go text eol=lf") {
		t.Fatalf(".gitattributes does not pin Go source files to LF")
	}

	cmd := exec.Command("git", "ls-files", "--", "*.go")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files *.go: %v", err)
	}
	for _, rel := range strings.Fields(string(out)) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- rel comes from git ls-files for tracked Go files.
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatalf("read tracked Go file %s: %v", rel, err)
		}
		if bytes.Contains(data, []byte("\r\n")) {
			t.Fatalf("tracked Go file %s contains CRLF line endings", rel)
		}
	}
}
