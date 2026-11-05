//go:build integration

package integration

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTarArchiveAcceptsPAXGlobalHeaderAndRejectsUnsafeEntries(t *testing.T) {
	t.Parallel()

	t.Run("PAX global metadata", func(t *testing.T) {
		archivePath := writeComposeRuntimeArchiveFixture(t, []tarFixtureEntry{
			{typeflag: tar.TypeXGlobalHeader, paxRecords: map[string]string{"comment": "packmon-test"}},
			{name: "nested/fixture.txt", typeflag: tar.TypeReg, body: "reviewed"},
		})
		destination := t.TempDir()
		if err := extractTarArchive(archivePath, destination); err != nil {
			t.Fatalf("extract archive with PAX global metadata: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(destination, "nested", "fixture.txt"))
		if err != nil {
			t.Fatalf("read extracted fixture: %v", err)
		}
		if got, want := string(data), "reviewed"; got != want {
			t.Fatalf("extracted fixture = %q, want %q", got, want)
		}
	})

	t.Run("parent traversal", func(t *testing.T) {
		archivePath := writeComposeRuntimeArchiveFixture(t, []tarFixtureEntry{{name: "../escape", typeflag: tar.TypeReg}})
		root := t.TempDir()
		destination := filepath.Join(root, "destination")
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatalf("create extraction destination: %v", err)
		}
		err := extractTarArchive(archivePath, destination)
		if err == nil || (!errors.Is(err, tar.ErrInsecurePath) && !strings.Contains(err.Error(), "unsafe path")) {
			t.Fatalf("extract error = %v, want tar insecure-path or helper unsafe-path error", err)
		}
		if _, err := os.Lstat(filepath.Join(root, "escape")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe archive created an outside file: %v", err)
		}
	})

	for _, tc := range []struct {
		name      string
		entry     tarFixtureEntry
		wantError string
	}{
		{name: "symlink", entry: tarFixtureEntry{name: "link", typeflag: tar.TypeSymlink}, wantError: "unsupported entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := writeComposeRuntimeArchiveFixture(t, []tarFixtureEntry{tc.entry})
			err := extractTarArchive(archivePath, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("extract error = %v, want text %q", err, tc.wantError)
			}
		})
	}
}

func TestYAMLVolumeMountQuotesTheCompleteShortSyntax(t *testing.T) {
	t.Parallel()
	got := yamlVolumeMount(filepath.Join("temporary root", "checkout"), "/workspace")
	want := `"temporary root/checkout:/workspace"`
	if got != want {
		t.Fatalf("quoted volume mount = %q, want %q", got, want)
	}
	if strings.Contains(got, `":/workspace`) {
		t.Fatalf("quoted volume mount closes the scalar before the container target: %s", got)
	}
}

type tarFixtureEntry struct {
	name       string
	typeflag   byte
	body       string
	paxRecords map[string]string
}

func writeComposeRuntimeArchiveFixture(t *testing.T, entries []tarFixtureEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar")
	file, err := os.Create(path) // #nosec G304 -- test-owned temporary path
	if err != nil {
		t.Fatalf("create archive fixture: %v", err)
	}
	writer := tar.NewWriter(file)
	t.Cleanup(func() {
		_ = writer.Close()
		_ = file.Close()
	})
	for _, entry := range entries {
		header := &tar.Header{Typeflag: entry.typeflag}
		if entry.typeflag == tar.TypeXGlobalHeader {
			header.PAXRecords = entry.paxRecords
		} else {
			header.Name = entry.name
			header.Mode = 0o600
			header.Size = int64(len(entry.body))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write archive fixture header: %v", err)
		}
		if entry.body != "" {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write archive fixture body: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive fixture writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive fixture file: %v", err)
	}
	return path
}
