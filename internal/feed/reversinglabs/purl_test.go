package reversinglabs

import (
	"strings"
	"testing"
)

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkg       string
		version   string
		want      string
		wantOK    bool
	}{
		{name: "npm", ecosystem: "npm", pkg: "left-pad", version: "1.3.0", want: "pkg:npm/left-pad@1.3.0", wantOK: true},
		{name: "npm scoped", ecosystem: "npm", pkg: "@scope/pkg", version: "2.0.0", want: "pkg:npm/%40scope/pkg@2.0.0", wantOK: true},
		{name: "pypi", ecosystem: "pypi", pkg: "requests", version: "2.32.0", want: "pkg:pypi/requests@2.32.0", wantOK: true},
		{name: "gem", ecosystem: "gem", pkg: "rails", version: "7.1.0", want: "pkg:gem/rails@7.1.0", wantOK: true},
		{name: "nuget", ecosystem: "nuget", pkg: "Newtonsoft.Json", version: "13.0.3", want: "pkg:nuget/Newtonsoft.Json@13.0.3", wantOK: true},
		{name: "maven", ecosystem: "maven", pkg: "org.slf4j:slf4j-api", version: "2.0.13", want: "pkg:maven/org.slf4j/slf4j-api@2.0.13", wantOK: true},
		{name: "pypi percent encodes reserved bytes", ecosystem: "pypi", pkg: "name with/slash%é?", version: "1.0.0+build/space %", want: "pkg:pypi/name%20with%2Fslash%25%C3%A9%3F@1.0.0%2Bbuild%2Fspace%20%25", wantOK: true},
		{name: "npm scoped percent encodes components", ecosystem: "npm", pkg: "@scope/pkg name", version: "2.0.0+meta", want: "pkg:npm/%40scope/pkg%20name@2.0.0%2Bmeta", wantOK: true},
		{name: "maven percent encodes artifact component", ecosystem: "maven", pkg: "com.example:core/lib", version: "3.0.0+meta", want: "pkg:maven/com.example/core%2Flib@3.0.0%2Bmeta", wantOK: true},
		{name: "unsupported ecosystem", ecosystem: "go", pkg: "github.com/acme/lib", version: "1.0.0", wantOK: false},
		{name: "missing version", ecosystem: "npm", pkg: "left-pad", wantOK: false},
		{name: "oversized name", ecosystem: "npm", pkg: strings.Repeat("a", 513), version: "1.0.0", wantOK: false},
		{name: "oversized version", ecosystem: "npm", pkg: "left-pad", version: strings.Repeat("1", 257), wantOK: false},
		{name: "malformed maven", ecosystem: "maven", pkg: "slf4j-api", version: "2.0.13", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BuildPURL(tt.ecosystem, tt.pkg, tt.version)
			if ok != tt.wantOK {
				t.Fatalf("BuildPURL ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("BuildPURL = %q, want %q", got, tt.want)
			}
			if SupportsPackage(tt.ecosystem, tt.pkg, tt.version) != tt.wantOK {
				t.Fatalf("SupportsPackage() mismatch")
			}
		})
	}
}
