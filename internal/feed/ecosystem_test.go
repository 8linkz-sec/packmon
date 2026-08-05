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
