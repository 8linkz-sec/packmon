package packagefilter

import (
	"reflect"
	"testing"
)

func TestNormalizeNamespacePrefixes(t *testing.T) {
	got := NormalizeNamespacePrefixes([]string{
		" NPM/@Internal/ ",
		"",
		"npm/@internal/",
		" @Scope/ ",
		"@scope/",
		"maven/com.acme:",
	})
	want := []string{"npm/@internal/", "@scope/", "maven/com.acme:"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeNamespacePrefixes() = %#v, want %#v", got, want)
	}
}

func TestExcludedByNamespace(t *testing.T) {
	tests := []struct {
		name      string
		prefixes  []string
		ecosystem string
		pkg       string
		want      bool
	}{
		{
			name:      "empty package is never excluded",
			prefixes:  []string{"npm/@internal/"},
			ecosystem: "npm",
			pkg:       " ",
			want:      false,
		},
		{
			name:      "ecosystem qualified prefix matches case-insensitively",
			prefixes:  []string{" NPM/@Internal/ "},
			ecosystem: "npm",
			pkg:       "@internal/widget",
			want:      true,
		},
		{
			name:      "qualified prefix does not match another ecosystem",
			prefixes:  []string{"npm/@internal/"},
			ecosystem: "pypi",
			pkg:       "@internal/widget",
			want:      false,
		},
		{
			name:      "raw name prefix matches without ecosystem",
			prefixes:  []string{"com.acme:"},
			ecosystem: "maven",
			pkg:       "com.acme:payments",
			want:      true,
		},
		{
			name:      "empty prefixes are ignored",
			prefixes:  []string{" ", ""},
			ecosystem: "npm",
			pkg:       "left-pad",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExcludedByNamespace(tt.prefixes, tt.ecosystem, tt.pkg); got != tt.want {
				t.Fatalf("ExcludedByNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}
