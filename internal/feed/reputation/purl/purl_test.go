package purl

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/feed/reputationpurl"
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

func TestCompatibilityPURLExactUnicodeByteLimits(t *testing.T) {
	exactName := strings.Repeat("é", 255) + "ab"
	exactVersion := strings.Repeat("é", 127) + "ab"
	encodedName := strings.Repeat("%C3%A9", 255) + "ab"
	encodedVersion := strings.Repeat("%C3%A9", 127) + "ab"
	if len(exactName) != checkcontract.MaxPackageNameLength || len(exactVersion) != checkcontract.MaxPackageVersionLength {
		t.Fatalf("fixture byte lengths = name %d, version %d; want %d,%d", len(exactName), len(exactVersion), checkcontract.MaxPackageNameLength, checkcontract.MaxPackageVersionLength)
	}

	tests := []struct {
		name    string
		pkg     string
		version string
		want    string
		wantOK  bool
	}{
		{
			name:    "exact name and version byte limits",
			pkg:     exactName,
			version: exactVersion,
			want:    "pkg:npm/" + encodedName + "@" + encodedVersion,
			wantOK:  true,
		},
		{
			name:    "one byte over name limit",
			pkg:     exactName + "c",
			version: exactVersion,
		},
		{
			name:    "one byte over version limit",
			pkg:     exactName,
			version: exactVersion + "c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BuildReversingLabsPURL("npm", tt.pkg, tt.version)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("BuildReversingLabsPURL() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
			canonical, canonicalOK := reputationpurl.BuildReversingLabsPURL("npm", tt.pkg, tt.version)
			if got != canonical || ok != canonicalOK {
				t.Fatalf("compatibility BuildReversingLabsPURL() = %q, %v; canonical = %q, %v", got, ok, canonical, canonicalOK)
			}
			supported := SupportsReversingLabsPackage("npm", tt.pkg, tt.version)
			canonicalSupported := reputationpurl.SupportsReversingLabsPackage("npm", tt.pkg, tt.version)
			if supported != tt.wantOK || supported != canonicalSupported {
				t.Fatalf("compatibility SupportsReversingLabsPackage() = %v; want %v and canonical %v", supported, tt.wantOK, canonicalSupported)
			}
		})
	}
}
