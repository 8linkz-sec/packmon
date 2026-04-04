package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestComposerParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewComposerParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"composer.lock", true},
		{"Composer.Lock", true}, // case-insensitive
		{"COMPOSER.LOCK", true},
		{"package-lock.json", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestComposerParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewComposerParser().Ecosystem(); got != domain.EcosystemComposer {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemComposer)
	}
}

func TestComposerParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "packages and packages-dev",
			input: `{
				"packages": [
					{"name": "monolog/monolog", "version": "v3.5.0"},
					{"name": "symfony/console", "version": "v7.0.4"}
				],
				"packages-dev": [
					{"name": "phpunit/phpunit", "version": "v11.0.3"}
				]
			}`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"monolog/monolog": "3.5.0",
				"symfony/console": "7.0.4",
				"phpunit/phpunit": "11.0.3",
			},
		},
		{
			name:      "empty packages array",
			input:     `{"packages": [], "packages-dev": []}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			input:   `{{{`,
			wantErr: true,
		},
		{
			name: "entry missing name",
			input: `{
				"packages": [
					{"name": "", "version": "1.0.0"},
					{"name": "good/pkg", "version": "2.0.0"}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"good/pkg": "2.0.0"},
			wantErr:   true,
		},
		{
			name: "v prefix stripped",
			input: `{
				"packages": [
					{"name": "vendor/pkg", "version": "v1.2.3"}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"vendor/pkg": "1.2.3"},
		},
		{
			name: "dedup across packages and packages-dev",
			input: `{
				"packages": [
					{"name": "vendor/pkg", "version": "v1.0.0"}
				],
				"packages-dev": [
					{"name": "vendor/pkg", "version": "v1.0.0"}
				]
			}`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewComposerParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if len(pkgs) != tt.wantCount {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemComposer {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemComposer)
				}
				if wantVer, ok := tt.wantPkgs[pkg.Name]; ok {
					if pkg.Version != wantVer {
						t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
					}
				}
			}
		})
	}
}
