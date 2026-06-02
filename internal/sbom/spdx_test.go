package sbom

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestParseSPDXJSONPackages(t *testing.T) {
	input := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[
			{
				"name":"lodash",
				"versionInfo":"4.17.21",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"}]
			},
			{
				"name":"django",
				"versionInfo":"4.2.11",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"PURL","referenceLocator":"pkg:pypi/django@4.2.11"}]
			},
			{
				"name":"no-purl",
				"versionInfo":"1.0.0",
				"externalRefs":[]
			}
		]
	}`)

	got, err := ParseSPDXJSON(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSPDXJSON() error = %v", err)
	}

	want := []domain.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
	if len(got.Skipped) != 1 {
		t.Fatalf("skipped = %d, want 1: %+v", len(got.Skipped), got.Skipped)
	}
}

func TestParseSPDXJSONSkipsNoAssertion(t *testing.T) {
	input := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[
			{"name":"NOASSERTION","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/noassertion@1.0.0"}]},
			{"name":"NONE","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/none@1.0.0"}]}
		]
	}`)

	got, err := ParseSPDXJSON(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSPDXJSON() error = %v", err)
	}
	if len(got.Packages) != 0 || len(got.Skipped) != 2 {
		t.Fatalf("packages=%d skipped=%d, want 0/2", len(got.Packages), len(got.Skipped))
	}
}

func TestParseSPDXJSONRejectsUnknownFormat(t *testing.T) {
	_, err := ParseSPDXJSON(strings.NewReader(`{"bomFormat":"CycloneDX"}`))
	if err == nil {
		t.Fatal("ParseSPDXJSON(unknown) error = nil")
	}
}
