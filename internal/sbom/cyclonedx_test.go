package sbom

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestParseCycloneDXJSONPackages(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"components":[
			{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},
			{"type":"framework","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"},
			{"type":"file","name":"README.md","version":"1.0.0","purl":"pkg:npm/readme@1.0.0"},
			{"type":"library","name":"noversion","purl":"pkg:npm/noversion"}
		]
	}`)

	got, err := ParseCycloneDX(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}

	want := []domain.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
	if len(got.Skipped) != 2 {
		t.Fatalf("skipped = %d, want 2: %+v", len(got.Skipped), got.Skipped)
	}
}

func TestParseCycloneDXXMLPackages(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5">
  <components>
    <component type="library">
      <name>left-pad</name>
      <version>1.3.0</version>
      <purl>pkg:npm/left-pad@1.3.0</purl>
    </component>
    <component type="application">
      <name>rails</name>
      <version>7.1.3</version>
      <purl>pkg:gem/rails@7.1.3</purl>
    </component>
  </components>
</bom>`)

	got, err := ParseCycloneDX(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCycloneDX(xml) error = %v", err)
	}

	want := []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "rails", Version: "7.1.3", Ecosystem: domain.EcosystemGem},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
}

func TestParseCycloneDXRejectsUnknownFormat(t *testing.T) {
	_, err := ParseCycloneDX(strings.NewReader(`{"spdxVersion":"SPDX-2.3"}`))
	if err == nil {
		t.Fatal("ParseCycloneDX(unknown) error = nil")
	}
}

func domainPackages(pkgs []Package) []domain.Package {
	out := make([]domain.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, pkg.Package)
	}
	return out
}
