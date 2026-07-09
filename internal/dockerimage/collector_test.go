package dockerimage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectFindsDockerfileAndComposeImages(t *testing.T) {
	root := t.TempDir()
	writeDockerImageTestFile(t, filepath.Join(root, "Dockerfile"), "FROM golang:1.26-alpine AS build\nFROM alpine:3.23 AS server\n")
	writeDockerImageTestFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  db:\n    image: postgres:18-alpine\n  app:\n    build:\n      context: .\n      target: server\n")

	collection, err := Collect(root, 5)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := make(map[string]Image)
	for _, img := range collection.Images {
		got[img.Ref.Name+"@"+img.Ref.Reference+"|"+img.SourceFile] = img
	}
	for _, key := range []string{
		"docker.io/library/golang@1.26-alpine|Dockerfile",
		"docker.io/library/alpine@3.23|Dockerfile",
		"docker.io/library/postgres@18-alpine|docker-compose.yml",
		"local/app@server|docker-compose.yml",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing %s in %#v", key, got)
		}
	}
	if collection.Files != 2 {
		t.Fatalf("Files = %d, want 2", collection.Files)
	}
}

func TestCollectRecordsParseErrorsAndContinues(t *testing.T) {
	root := t.TempDir()
	writeDockerImageTestFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeDockerImageTestFile(t, filepath.Join(root, "compose.yml"), "services:\n  broken: [")

	collection, err := Collect(root, 5)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(collection.Images) != 1 {
		t.Fatalf("Images = %#v, want one Dockerfile image", collection.Images)
	}
	if len(collection.ParseErrors) != 1 {
		t.Fatalf("ParseErrors = %#v, want one compose parse error", collection.ParseErrors)
	}
}

func TestCollectRejectsDockerfileSymlinkOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideDockerfile := filepath.Join(outside, "Dockerfile")
	writeDockerImageTestFile(t, outsideDockerfile, "FROM ghcr.io/acme/escaped:9.9.9\n")
	symlinkOrSkip(t, outsideDockerfile, filepath.Join(root, "Dockerfile"))

	collection, err := Collect(root, 5)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(collection.Images) != 0 {
		t.Fatalf("Images = %#v, want no images from external symlink target", collection.Images)
	}
	if len(collection.ParseErrors) != 1 || !strings.Contains(collection.ParseErrors[0], "Dockerfile") {
		t.Fatalf("ParseErrors = %#v, want symlinked Dockerfile rejection", collection.ParseErrors)
	}
}

func TestParseFileRejectsRelativeEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideDockerfile := filepath.Join(outside, "Dockerfile")
	writeDockerImageTestFile(t, outsideDockerfile, "FROM ghcr.io/acme/escaped:9.9.9\n")

	_, err := parseFile(File{
		Path:    outsideDockerfile,
		RelPath: filepath.ToSlash(filepath.Join("..", "outside", "Dockerfile")),
		Kind:    KindDockerfile,
	})
	if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
		t.Fatalf("parseFile() error = %v, want root escape rejection", err)
	}
}

func TestParseFileRejectsOversizedInventoryBeforeParsing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "compose.yaml")
	writeDockerImageTestFile(t, path, "services: {}\n")
	if err := os.Truncate(path, maxDockerInventoryFileSize+1); err != nil {
		t.Fatal(err)
	}

	_, err := parseFile(File{Path: path, RelPath: "compose.yaml", Kind: KindCompose})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum docker inventory size") {
		t.Fatalf("parseFile() error = %v, want size-limit error", err)
	}
}

func writeDockerImageTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}
