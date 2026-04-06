package feed

import (
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestMapGHSAEcosystem_GitHubActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "legacy actions token", input: "actions"},
		{name: "new GitHub Actions label", input: "GitHub Actions"},
		{name: "mixed case GitHub Actions label", input: "github actions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := MapGHSAEcosystem(tt.input)
			if !ok {
				t.Fatalf("MapGHSAEcosystem(%q) reported unsupported ecosystem", tt.input)
			}
			if got != domain.EcosystemGitHubActions {
				t.Fatalf("MapGHSAEcosystem(%q) = %q, want %q", tt.input, got, domain.EcosystemGitHubActions)
			}
		})
	}
}

func TestMapGHSAEcosystem_AliasValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  domain.Ecosystem
	}{
		{input: "PyPI", want: domain.EcosystemPyPI},
		{input: "packagist", want: domain.EcosystemComposer},
		{input: "swifturl", want: domain.EcosystemSwiftPM},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := MapGHSAEcosystem(tt.input)
			if !ok {
				t.Fatalf("MapGHSAEcosystem(%q) reported unsupported ecosystem", tt.input)
			}
			if got != tt.want {
				t.Fatalf("MapGHSAEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
