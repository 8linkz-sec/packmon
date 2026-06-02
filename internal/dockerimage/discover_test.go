package dockerimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFilesFindsDockerfilesAndComposeFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "Dockerfile.cli"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  db:\n    image: postgres:18-alpine\n")
	writeTestFile(t, filepath.Join(root, "node_modules", "pkg", "Dockerfile"), "FROM ignored:latest\n")
	writeTestFile(t, filepath.Join(root, "deep", "too", "far", "Dockerfile"), "FROM ignored:latest\n")

	files, err := DiscoverFiles(root, 2)
	if err != nil {
		t.Fatalf("DiscoverFiles: %v", err)
	}
	got := make(map[string]Kind)
	for _, file := range files {
		got[file.RelPath] = file.Kind
	}
	want := map[string]Kind{
		"Dockerfile":         KindDockerfile,
		"Dockerfile.cli":     KindDockerfile,
		"docker-compose.yml": KindCompose,
	}
	if len(got) != len(want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Fatalf("files[%q] = %q, want %q; all files %#v", path, got[path], kind, got)
		}
	}
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
