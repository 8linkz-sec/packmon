package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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
		wantDev   map[string]bool
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
				"monolog/monolog": "v3.5.0",
				"symfony/console": "v7.0.4",
				"phpunit/phpunit": "v11.0.3",
			},
			// packages-dev entries must be flagged as dev so the scanner can
			// filter them unless --include-dev is set.
			wantDev: map[string]bool{
				"monolog/monolog": false,
				"symfony/console": false,
				"phpunit/phpunit": true,
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
			name: "v prefix preserved",
			input: `{
				"packages": [
					{"name": "vendor/pkg", "version": "v1.2.3"}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"vendor/pkg": "v1.2.3"},
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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				if tt.wantErr {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemComposer)
			for _, pkg := range pkgs {
				if wantDev, ok := tt.wantDev[pkg.Name]; ok {
					if pkg.Dev != wantDev {
						t.Errorf("package %q Dev = %v, want %v", pkg.Name, pkg.Dev, wantDev)
					}
				}
			}
		})
	}
}
