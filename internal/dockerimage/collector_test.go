package dockerimage

import (
	"errors"
	"io"
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

func TestLimitedDockerInventoryReaderAllowsExactLimit(t *testing.T) {
	reader := &limitedDockerInventoryReader{
		r:    strings.NewReader("a"),
		read: maxDockerInventoryFileSize - 1,
	}
	buf := make([]byte, 2)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("first Read() = %d, %v; want 1, nil", n, err)
	}
	n, err = reader.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("second Read() = %d, %v; want 0, EOF", n, err)
	}
}

func TestLimitedDockerInventoryReaderRejectsBytePastLimit(t *testing.T) {
	reader := &limitedDockerInventoryReader{
		r:    strings.NewReader("ab"),
		read: maxDockerInventoryFileSize - 1,
	}
	buf := make([]byte, 2)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("first Read() = %d, %v; want 1, nil", n, err)
	}
	n, err = reader.Read(buf)
	if n != 0 || err == nil || !strings.Contains(err.Error(), "exceeds maximum docker inventory size") {
		t.Fatalf("second Read() = %d, %v; want size-limit error", n, err)
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
