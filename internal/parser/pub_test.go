package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPubParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewPubParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"pubspec.lock", true},
		{"Pubspec.lock", false},
		{"pubspec.yaml", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestPubParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewPubParser().Ecosystem(); got != domain.EcosystemPub {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPub)
	}
}

func TestPubParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid pubspec.lock",
			input: `packages:
  http:
    version: "1.2.1"
  path:
    version: "1.9.0"
  collection:
    version: "1.18.0"
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"http":       "1.2.1",
				"path":       "1.9.0",
				"collection": "1.18.0",
			},
		},
		{
			name:      "empty packages map",
			input:     `packages:`,
			wantCount: 0,
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:    "invalid yaml",
			input:   `{{{not yaml`,
			wantErr: true,
		},
		{
			name: "package with empty version",
			input: `packages:
  http:
    version: "1.2.1"
  bad:
    version: ""
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"http": "1.2.1"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewPubParser().Parse(strings.NewReader(tt.input))
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
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemPub)
		})
	}
}

func TestPubParserParseReadError(t *testing.T) {
	t.Parallel()

	packages, err := NewPubParser().Parse(errorReader{})
	if err == nil || !strings.Contains(err.Error(), "pub: reading input: forced read error") {
		t.Fatalf("Parse(read error) = %v, want contextual read error", err)
	}
	if packages != nil {
		t.Fatalf("packages = %#v, want nil", packages)
	}
}

func TestPubSourceRefsSupportsBothYAMLMapShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		description any
		want        []string
	}{
		{
			name:        "string keys",
			description: map[string]any{"url": "https://pub.example.test/private"},
			want:        []string{"url=https://pub.example.test/private"},
		},
		{
			name:        "interface keys",
			description: map[any]any{"url": "https://pub.example.test/legacy"},
			want:        []string{"url=https://pub.example.test/legacy"},
		},
		{
			name:        "blank and non-string URLs ignored",
			description: map[any]any{"url": "  ", "other": 1},
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pubSourceRefs(pubspecPackage{Description: tt.description})
			if !equalStrings(got, tt.want) {
				t.Fatalf("pubSourceRefs() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := pubSourceRefs(pubspecPackage{Source: " hosted ", Description: map[string]any{"url": "https://pub.example.test/hosted"}}); !equalStrings(got, []string{"source=hosted", "url=https://pub.example.test/hosted"}) {
		t.Fatalf("pubSourceRefs(source and URL) = %q", got)
	}
}
