//go:build integration

package integration

import (
	"archive/tar"
	"encoding/base64"
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

func TestValidateCompletedBootstrapEnvironmentUsesEffectiveAssignments(t *testing.T) {
	t.Parallel()

	const preservedDatabasePassword = "fixture-owner-only-database-password"
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := strings.Join([]string{
		"POSTGRES_USER=existing-owner",
		"POSTGRES_DB=existing-database",
		"POSTGRES_PASSWORD=" + preservedDatabasePassword,
		"PACKMON_DB_PASSWORD=" + preservedDatabasePassword,
		"PACKMON_ADMIN_INITIAL_PASSWORD=generated-admin-password",
		"PACKMON_ENCRYPTION_KEY=" + validKey,
		"PACKMON_ADMIN_AUDIT_HMAC_KEY=" + validKey,
	}, "\n") + "\n"
	if err := validateCompletedBootstrapEnvironment([]byte(valid), preservedDatabasePassword); err != nil {
		t.Fatalf("valid completed bootstrap environment: %v", err)
	}

	for _, tc := range []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "comment is not an assignment",
			data:    strings.Replace(valid, "POSTGRES_USER=existing-owner", "# POSTGRES_USER=existing-owner", 1),
			wantErr: "POSTGRES_USER assignment count = 0",
		},
		{
			name:    "prepended duplicate is rejected",
			data:    "POSTGRES_PASSWORD=ineffective-prepended-value\n" + valid,
			wantErr: "POSTGRES_PASSWORD assignment count = 2",
		},
		{
			name:    "preserved value must remain exact",
			data:    strings.Replace(valid, "POSTGRES_DB=existing-database", "POSTGRES_DB=replaced", 1),
			wantErr: "POSTGRES_DB did not preserve",
		},
		{
			name:    "generated secret must be valid",
			data:    strings.Replace(valid, "PACKMON_ENCRYPTION_KEY="+validKey, "PACKMON_ENCRYPTION_KEY=not-base64", 1),
			wantErr: "PACKMON_ENCRYPTION_KEY is invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCompletedBootstrapEnvironment([]byte(tc.data), preservedDatabasePassword)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validation error = %v, want text %q", err, tc.wantErr)
			}
		})
	}
}

func TestComposeRuntimeScenarioDiagnosticRedactsExternalMountPaths(t *testing.T) {
	t.Parallel()

	scenarioDir := filepath.Join(t.TempDir(), "scenario")
	checkout := filepath.Join(t.TempDir(), "owner checkout")
	envPath := filepath.Join(checkout, ".env")
	s := &composeRuntimeScenario{
		h:                      &composeRuntimeHarness{},
		t:                      t,
		dir:                    scenarioDir,
		diagnosticReplacements: make(map[string]string),
	}
	s.redactDiagnosticPath(checkout, "[CHECKOUT]")
	s.redactDiagnosticPath(envPath, "[CHECKOUT_ENV]")

	diagnostic := s.diagnostic(strings.Join([]string{
		scenarioDir,
		filepath.ToSlash(scenarioDir),
		checkout,
		filepath.ToSlash(checkout),
		envPath,
		filepath.ToSlash(envPath),
	}, "\n"))
	for _, path := range []string{scenarioDir, filepath.ToSlash(scenarioDir), checkout, filepath.ToSlash(checkout), envPath, filepath.ToSlash(envPath)} {
		if strings.Contains(diagnostic, path) {
			t.Fatalf("diagnostic retained an absolute scenario or bind path: %s", diagnostic)
		}
	}
	for _, marker := range []string{"[SCENARIO]", "[CHECKOUT]"} {
		if !strings.Contains(diagnostic, marker) {
			t.Fatalf("diagnostic = %q, want redaction marker %s", diagnostic, marker)
		}
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
