package purl

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
)

func TestBuildReversingLabsPURL(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkg       string
		version   string
		want      string
		wantOK    bool
	}{
		{"pypi escapes name and version", " PyPI ", "requests extra", "1.0+meta", "pkg:pypi/requests%20extra@1.0%2Bmeta", true},
		{"npm unscoped", "npm", "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0", true},
		{"npm scoped", "npm", "@angular/core", "17.3.12", "pkg:npm/%40angular/core@17.3.12", true},
		{"maven coordinate", "maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true},
		{"unsupported ecosystem", "go", "github.com/gin-gonic/gin", "v1.9.1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BuildReversingLabsPURL(tt.ecosystem, tt.pkg, tt.version)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("BuildReversingLabsPURL() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
			if supported := SupportsReversingLabsPackage(tt.ecosystem, tt.pkg, tt.version); supported != tt.wantOK {
				t.Fatalf("SupportsReversingLabsPackage() = %v, want %v", supported, tt.wantOK)
			}
		})
	}
}

func TestBuildReversingLabsPURLRejectsOverlongCoordinates(t *testing.T) {
	if MaxPackageNameLength != checkcontract.MaxPackageNameLength {
		t.Fatalf("MaxPackageNameLength = %d, want shared contract %d", MaxPackageNameLength, checkcontract.MaxPackageNameLength)
	}
	if MaxPackageVersionLength != checkcontract.MaxPackageVersionLength {
		t.Fatalf("MaxPackageVersionLength = %d, want shared contract %d", MaxPackageVersionLength, checkcontract.MaxPackageVersionLength)
	}
	if got, ok := BuildReversingLabsPURL("npm", strings.Repeat("a", checkcontract.MaxPackageNameLength+1), "1.0.0"); ok || got != "" {
		t.Fatalf("overlong name = %q, %v", got, ok)
	}
	if got, ok := BuildReversingLabsPURL("npm", "left-pad", strings.Repeat("1", checkcontract.MaxPackageVersionLength+1)); ok || got != "" {
		t.Fatalf("overlong version = %q, %v", got, ok)
	}
}
