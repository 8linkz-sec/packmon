package feed

import (
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestEcosystemMappingHelpers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		fn   func(string) (domain.Ecosystem, bool)
		in   string
		want domain.Ecosystem
	}{
		{name: "osv pypi", fn: MapOSVEcosystem, in: "PyPI", want: domain.EcosystemPyPI},
		{name: "osv alias cargo", fn: MapOSVEcosystem, in: "cargo", want: domain.EcosystemCargo},
		{name: "osv github actions", fn: MapOSVEcosystem, in: "GitHub Actions", want: domain.EcosystemGitHubActions},
		{name: "ghsa actions", fn: MapGHSAEcosystem, in: "GitHub Actions", want: domain.EcosystemGitHubActions},
		{name: "ghsa pip", fn: MapGHSAEcosystem, in: "pip", want: domain.EcosystemPyPI},
		{name: "openssf crates", fn: MapOpenSSFEcosystem, in: "crates.io", want: domain.EcosystemCargo},
		{name: "openssf go alias", fn: MapOpenSSFEcosystem, in: "go", want: domain.EcosystemGo},
		{name: "openssf rubygems alias", fn: MapOpenSSFEcosystem, in: "RubyGems", want: domain.EcosystemGem},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.fn(tt.in)
			if !ok || got != tt.want {
				t.Fatalf("mapping(%q) = %q, %v; want %q true", tt.in, got, ok, tt.want)
			}
		})
	}

	if got, ok := MapOSVEcosystem("unknown"); ok || got != "" {
		t.Fatalf("MapOSVEcosystem(unknown) = %q, %v; want empty false", got, ok)
	}
	if got, ok := MapGHSAEcosystem("unknown"); ok || got != "" {
		t.Fatalf("MapGHSAEcosystem(unknown) = %q, %v; want empty false", got, ok)
	}
	if got, ok := MapOpenSSFEcosystem("unknown"); ok || got != "" {
		t.Fatalf("MapOpenSSFEcosystem(unknown) = %q, %v; want empty false", got, ok)
	}
}

func TestOSVBucketEcosystemsIncludesSupportedBuckets(t *testing.T) {
	t.Parallel()

	buckets := OSVBucketEcosystems()
	for _, want := range []string{"npm", "PyPI", "Go", "Maven", "crates.io", "CRAN", "GitHub Actions"} {
		if !slices.Contains(buckets, want) {
			t.Fatalf("OSVBucketEcosystems() = %#v, missing %q", buckets, want)
		}
	}
}

// TestFeedEcosystemMapsNeverYieldInventoryOnlyEcosystems pins that no feed
// name maps to an inventory-only ecosystem (docker, chocolatey): those never
// receive feed advisories, so a mapping to them would silently store
// unmatched data.
func TestFeedEcosystemMapsNeverYieldInventoryOnlyEcosystems(t *testing.T) {
	t.Parallel()

	for name, m := range map[string]map[string]domain.Ecosystem{
		"osv":     osvEcosystemMap,
		"ghsa":    ghsaEcosystemMap,
		"openssf": openssfEcosystemMap,
	} {
		for feedName, ecosystem := range m {
			if !ecosystem.ScanInput() {
				t.Errorf("%s map entry %q -> %q is not a scan ecosystem", name, feedName, ecosystem)
			}
		}
	}
	for _, inventoryOnly := range []string{"docker", "chocolatey", "Chocolatey", "Docker"} {
		if got, ok := MapOSVEcosystem(inventoryOnly); ok {
			t.Errorf("MapOSVEcosystem(%q) = %q, want unmapped", inventoryOnly, got)
		}
		if got, ok := MapGHSAEcosystem(inventoryOnly); ok {
			t.Errorf("MapGHSAEcosystem(%q) = %q, want unmapped", inventoryOnly, got)
		}
		if got, ok := MapOpenSSFEcosystem(inventoryOnly); ok {
			t.Errorf("MapOpenSSFEcosystem(%q) = %q, want unmapped", inventoryOnly, got)
		}
	}
	for _, bucket := range OSVBucketEcosystems() {
		if eco, ok := MapOSVEcosystem(bucket); !ok || !eco.ScanInput() {
			t.Errorf("OSV bucket %q maps to %q (ok=%v), want a scan ecosystem", bucket, eco, ok)
		}
	}
}
