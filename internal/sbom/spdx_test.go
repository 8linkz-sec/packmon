package sbom

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
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

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got.Packages) != 0 || len(got.Skipped) != 2 {
		t.Fatalf("packages=%d skipped=%d, want 0/2", len(got.Packages), len(got.Skipped))
	}
}

func TestParseRejectsUnknownSPDXFormat(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"spdxVersion":"not-spdx"}`))
	if err == nil {
		t.Fatal("Parse(unknown) error = nil")
	}
}

func TestParseSPDXJSONClassifiesInvalidAndUnsupportedEntries(t *testing.T) {
	input := []byte(`{
		"spdxVersion":" SPDX-2.3 ",
		"packages":[
			{"name":"   ","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/ignored@1.0.0"}]},
			{"name":"missing","externalRefs":[]},
			{"name":"unsupported","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:unknown/unsupported@1.0.0"}]},
			{"name":"kept","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/kept@1.0.0"}]}
		]
	}`)

	got, err := parseSPDXJSON(input)
	if err != nil {
		t.Fatalf("parseSPDXJSON() error = %v", err)
	}
	if want := []Package{{Package: domain.Package{Name: "kept", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}, PURL: "pkg:npm/kept@1.0.0", Source: "spdx"}}; !reflect.DeepEqual(got.Packages, want) {
		t.Fatalf("packages = %#v, want %#v", got.Packages, want)
	}
	wantSkipped := []SkippedComponent{
		{Name: "", Reason: "invalid package name"},
		{Name: "missing", Reason: "missing purl"},
		{Name: "unsupported", Reason: "unsupported or versionless purl"},
	}
	if !reflect.DeepEqual(got.Skipped, wantSkipped) {
		t.Fatalf("skipped = %#v, want %#v", got.Skipped, wantSkipped)
	}
}

func TestIsSPDXJSONRequiresDecodableSPDXPrefix(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "trimmed prefix", data: []byte(`{"spdxVersion":"  SPDX-3.0 "}`), want: true},
		{name: "missing version", data: []byte(`{"packages":[]}`), want: false},
		{name: "malformed JSON", data: []byte(`{"spdxVersion":`), want: false},
		{name: "other format", data: []byte(`{"spdxVersion":"not-spdx"}`), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSPDXJSON(tt.data); got != tt.want {
				t.Fatalf("IsSPDXJSON(%s) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestSPDXPackagePURLSkipsBlankAndNonPURLReferences(t *testing.T) {
	pkg := spdxPackage{ExternalRefs: []spdxExternalRef{
		{ReferenceType: "cpe23Type", ReferenceLocator: "cpe:2.3:a:example"},
		{ReferenceType: " PURL ", ReferenceLocator: "   "},
		{ReferenceType: "purl", ReferenceLocator: " pkg:npm/example@1.2.3 "},
	}}
	if got, want := spdxPackagePURL(pkg), "pkg:npm/example@1.2.3"; got != want {
		t.Fatalf("spdxPackagePURL() = %q, want %q", got, want)
	}
}
