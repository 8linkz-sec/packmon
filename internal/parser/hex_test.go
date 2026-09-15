package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestHexParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewHexParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"mix.lock", true},
		{"Mix.lock", false},
		{"mix.exs", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestHexParser_ParseReportsReadError(t *testing.T) {
	pkgs, err := NewHexParser().Parse(errorReader{})
	if err == nil || !strings.Contains(err.Error(), "reading input: forced read error") {
		t.Fatalf("Parse(read error) = %v, want wrapped read error", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("Parse(read error) packages = %#v, want none", pkgs)
	}
}

func TestHexRepositoryFromLockLineRejectsIncompleteAndMalformedTuples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "no hex tuple",
			line: `"package": {:path, "../package"},`,
		},
		{
			name: "too few fields",
			line: `"package": {:hex, :package, "1.0.0", "hash"},`,
		},
		{
			name: "repository is not a quoted string",
			line: `"package": {:hex, :package, "1.0.0", "hash", [:mix], [], :hexpm, "hash"},`,
		},
		{
			name: "repository is empty after trimming",
			line: `"package": {:hex, :package, "1.0.0", "hash", [:mix], [], "  ", "hash"},`,
		},
		{
			name: "nested tuples and comma inside quoted values do not shift repository",
			line: `"package": {:hex, :package, "1.0.0", "hash", [:mix], [{:dep, "~> 1.0", [repo: "other,repo"]}], "private_hex", "hash"},`,
			want: "private_hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hexRepositoryFromLockLine(tt.line); got != tt.want {
				t.Fatalf("hexRepositoryFromLockLine(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestHexStringFieldValueRejectsEmptyAndInvalidQuotedValues(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "   ", `"unterminated`, "not-a-string"} {
		if got := hexStringFieldValue(raw); got != "" {
			t.Errorf("hexStringFieldValue(%q) = %q, want empty", raw, got)
		}
	}
}

func TestHexParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewHexParser().Ecosystem(); got != domain.EcosystemHex {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemHex)
	}
}

func TestHexParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid mix.lock",
			input: `%{
  "jason": {:hex, :jason, "1.4.1", "af1c63c72f3135dd2cba27fdb80cdcfb824e9710e22cbd0b046ecf1200913034", [:mix], [], "hexpm", "fba22f9b4ba3b6cd7ca80b2bbd63e429d3241de8d99cd3de4aebe7d46b03bd09"},
  "phoenix": {:hex, :phoenix, "1.7.12", "abc123", [:mix], [{:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: false]}], "hexpm", "def456"},
  "plug": {:hex, :plug, "1.15.3", "ghi789", [:mix], [], "hexpm", "jkl012"},
}
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"jason":   "1.4.1",
				"phoenix": "1.7.12",
				"plug":    "1.15.3",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "only map delimiters",
			input:     "%{\n}\n",
			wantCount: 0,
		},
		{
			name: "non-hex entries skipped",
			input: `%{
  "jason": {:hex, :jason, "1.4.1", "hash", [:mix], [], "hexpm", "hash"},
  "local_dep": {:path, "../local_dep"},
}
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"jason": "1.4.1"},
		},
		{
			name: "quoted package fields",
			input: `%{
  "plug-cowboy": {:hex, :"plug-cowboy", "2.7.1", "hash", [:mix], [], "hexpm", "hash"},
  "typed_struct": {:hex, "typed_struct", "0.3.0", "hash", [:mix], [], "hexpm", "hash"},
}
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"plug-cowboy":  "2.7.1",
				"typed_struct": "0.3.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewHexParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemHex)
		})
	}
}
