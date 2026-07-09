package sbomgen

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestAutoSBOMManifestDescriptorsCoverPythonTargets(t *testing.T) {
	descriptors := autoSBOMManifestDescriptors()
	got := map[string]autoSBOMManifestDescriptor{}
	for _, descriptor := range descriptors {
		got[descriptor.Name] = descriptor
	}

	want := map[string]autoSBOMManifestDescriptor{
		"requirements.txt": {
			Name:           "requirements.txt",
			Kind:           autoSBOMManifestKindDetect,
			Ecosystem:      domain.EcosystemPyPI,
			InputKind:      "requirements",
			RequirementIDs: []string{"python", "cyclonedx-py"},
		},
		"pyproject.toml": {
			Name:           "pyproject.toml",
			Kind:           autoSBOMManifestKindPoetryPyproject,
			Ecosystem:      domain.EcosystemPyPI,
			InputKind:      "poetry",
			RequirementIDs: []string{"python", "cyclonedx-py"},
		},
		"Pipfile": {
			Name: "Pipfile",
			Kind: autoSBOMManifestKindUnsupported,
		},
		"Pipfile.lock": {
			Name: "Pipfile.lock",
			Kind: autoSBOMManifestKindUnsupported,
		},
		"poetry.lock": {
			Name: "poetry.lock",
			Kind: autoSBOMManifestKindSupportFile,
		},
	}

	for name, wantDescriptor := range want {
		if !reflect.DeepEqual(got[name], wantDescriptor) {
			t.Fatalf("descriptor %s = %#v, want %#v", name, got[name], wantDescriptor)
		}
	}
}

func TestRequirementScriptsReadAutoSBOMManifestSupportSource(t *testing.T) {
	root := repoRootForSBOMTest(t)
	for _, rel := range []string{
		filepath.Join("scripts", "lib", "requirements.sh"),
		filepath.Join("scripts", "lib", "requirements.ps1"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // test reads static repository scripts.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(data), filepath.ToSlash(autoSBOMManifestSupportPath)) &&
			!strings.Contains(string(data), strings.ReplaceAll(autoSBOMManifestSupportPath, "/", `\`)) {
			t.Fatalf("%s must read %s to avoid auto-SBOM target drift", rel, autoSBOMManifestSupportPath)
		}
	}
}

func repoRootForSBOMTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}
