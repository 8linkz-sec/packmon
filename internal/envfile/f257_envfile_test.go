package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestF257ParseRenderAndLookupEdges(t *testing.T) {
	t.Parallel()

	entries := Parse([]byte("=orphan\rRAW\r"))
	if len(entries) != 2 || entries[0].Key != "" || entries[0].Raw != "=orphan" {
		t.Fatalf("Parse(empty key) = %#v, want preserved raw line", entries)
	}
	if value, ok := Value(entries, "MISSING"); ok || value != "" {
		t.Fatalf("Value(missing) = %q, %v; want empty, false", value, ok)
	}
	if got := string(Render([]Entry{{Raw: "# retained"}})); got != "# retained\n" {
		t.Fatalf("Render(raw entry) = %q", got)
	}
}

func TestF257LoadAndWriteErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if entries, err := Load(dir); err == nil || entries != nil {
		t.Fatalf("Load(directory) = %#v, %v; want read error", entries, err)
	}

	missingParent := filepath.Join(dir, "missing", ".env")
	if err := WriteAtomic(missingParent, []byte("A=1\n"), 0o600); err == nil {
		t.Fatal("WriteAtomic(missing parent) error = nil")
	}

	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("Mkdir target: %v", err)
	}
	if err := WriteAtomic(targetDir, []byte("A=1\n"), 0o600); err == nil {
		t.Fatal("WriteAtomic(directory target) error = nil")
	}
}
