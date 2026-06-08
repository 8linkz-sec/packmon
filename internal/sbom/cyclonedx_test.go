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

func TestParseCycloneDXJSONDependencyGraphMetadata(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{
			"component":{"type":"application","name":"app","bom-ref":"app","purl":"pkg:npm/app@1.0.0"}
		},
		"components":[
			{"type":"library","name":"cli","version":"4.3.0","bom-ref":"app|@tailwindcss/cli@4.3.0","purl":"pkg:npm/%40tailwindcss/cli@4.3.0"},
			{"type":"library","name":"watcher","version":"2.5.6","bom-ref":"app|@parcel/watcher@2.5.6","purl":"pkg:npm/%40parcel/watcher@2.5.6"},
			{"type":"library","name":"node-addon-api","version":"7.1.1","bom-ref":"app|node-addon-api@7.1.1","purl":"pkg:npm/node-addon-api@7.1.1"}
		],
		"dependencies":[
			{"ref":"app","dependsOn":["app|@tailwindcss/cli@4.3.0"]},
			{"ref":"app|@tailwindcss/cli@4.3.0","dependsOn":["app|@parcel/watcher@2.5.6"]},
			{"ref":"app|@parcel/watcher@2.5.6","dependsOn":["app|node-addon-api@7.1.1"]}
		]
	}`)

	got, err := ParseCycloneDX(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}

	byName := make(map[string]domain.Package)
	for _, item := range got.Packages {
		byName[item.Package.Name] = item.Package
	}

	cli := byName["@tailwindcss/cli"]
	if !cli.Direct || cli.Indirect {
		t.Fatalf("cli direct=%v indirect=%v, want direct root dependency", cli.Direct, cli.Indirect)
	}

	watcher := byName["@parcel/watcher"]
	if watcher.Direct || !watcher.Indirect || len(watcher.Via) != 1 || watcher.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("watcher metadata = %+v, want indirect via @tailwindcss/cli", watcher)
	}
	if len(watcher.Parents) != 1 || watcher.Parents[0].Name != "@tailwindcss/cli" || watcher.Parents[0].Version != "4.3.0" {
		t.Fatalf("watcher parents = %+v, want @tailwindcss/cli@4.3.0", watcher.Parents)
	}

	nodeAddon := byName["node-addon-api"]
	if nodeAddon.Direct || !nodeAddon.Indirect || len(nodeAddon.Via) != 1 || nodeAddon.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("node-addon-api metadata = %+v, want indirect via @tailwindcss/cli", nodeAddon)
	}
	if len(nodeAddon.Parents) != 1 || nodeAddon.Parents[0].Name != "@parcel/watcher" || nodeAddon.Parents[0].Version != "2.5.6" {
		t.Fatalf("node-addon-api parents = %+v, want @parcel/watcher@2.5.6", nodeAddon.Parents)
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
