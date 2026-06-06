package sbomgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGeneratedSBOMRequiresCycloneDXJSON(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "bom.xml")
	if err := os.WriteFile(xmlPath, []byte(`<bom><components></components></bom>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateGeneratedSBOM(xmlPath); err == nil || !strings.Contains(err.Error(), "CycloneDX JSON") {
		t.Fatalf("validate XML err = %v, want CycloneDX JSON rejection", err)
	}
}

func TestValidateGeneratedSBOMCountsPackagesAndSkippedComponents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.cdx.json")
	content := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
    {"type":"library","name":"missing-purl","version":"1.0.0"}
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	packages, skipped, err := validateGeneratedSBOM(path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if packages != 1 || skipped != 1 {
		t.Fatalf("packages/skipped = %d/%d, want 1/1", packages, skipped)
	}
}
