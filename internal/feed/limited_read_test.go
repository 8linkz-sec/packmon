package feed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRootFileLimitedRejectsOversizedRegularFile(t *testing.T) {
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "advisory.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, MaxGitAdvisoryJSONSize+1); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	_, err = ReadRootFileLimited(root, "advisory.json", MaxGitAdvisoryJSONSize)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum advisory JSON size") {
		t.Fatalf("ReadRootFileLimited() error = %v, want size-limit error", err)
	}
}

func TestReadRootFileLimitedReadsSmallFile(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "advisory.json"), []byte(`{"id":"GHSA-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	data, err := ReadRootFileLimited(root, "advisory.json", MaxGitAdvisoryJSONSize)
	if err != nil {
		t.Fatalf("ReadRootFileLimited() error = %v", err)
	}
	if string(data) != `{"id":"GHSA-test"}` {
		t.Fatalf("ReadRootFileLimited() = %q", data)
	}
}
