package sbom

import (
	"reflect"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPackageFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want domain.Package
		ok   bool
	}{
		{"pkg:npm/%40scope/name@1.2.3", domain.Package{Name: "@scope/name", Version: "1.2.3", Ecosystem: domain.EcosystemNPM}, true},
		{"pkg:npm/example@1.0.0%2Bbuild.1", domain.Package{Name: "example", Version: "1.0.0+build.1", Ecosystem: domain.EcosystemNPM}, true},
		{"pkg:npm/foo@1.0.0?vcs_url=git@github.com:o/r", domain.Package{Name: "foo", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}, true},
		{"pkg:pypi/Django@4.2.11", domain.Package{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI}, true},
		{"pkg:pypi/my.pkg_Name@1.0.0", domain.Package{Name: "my-pkg-name", Version: "1.0.0", Ecosystem: domain.EcosystemPyPI}, true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", domain.Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.17.1", Ecosystem: domain.EcosystemMaven}, true},
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.1", domain.Package{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: domain.EcosystemGo}, true},
		{"pkg:cargo/serde@1.0.0", domain.Package{Name: "serde", Version: "1.0.0", Ecosystem: domain.EcosystemCargo}, true},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", domain.Package{Name: "newtonsoft.json", Version: "13.0.3", Ecosystem: domain.EcosystemNuGet}, true},
		{"pkg:composer/laravel/framework@10.48.0", domain.Package{Name: "laravel/framework", Version: "10.48.0", Ecosystem: domain.EcosystemComposer}, true},
		{"pkg:gem/rails@7.1.3", domain.Package{Name: "rails", Version: "7.1.3", Ecosystem: domain.EcosystemGem}, true},
		{"pkg:pub/http@1.2.1", domain.Package{Name: "http", Version: "1.2.1", Ecosystem: domain.EcosystemPub}, true},
		{"pkg:cocoapods/AFNetworking@4.0.1", domain.Package{Name: "AFNetworking", Version: "4.0.1", Ecosystem: domain.EcosystemCocoaPods}, true},
		{"pkg:swift/github.com/apple/swift-nio@2.66.0", domain.Package{Name: "github.com/apple/swift-nio", Version: "2.66.0", Ecosystem: domain.EcosystemSwiftPM}, true},
		{"pkg:swift/github.com/apple/swift-nio.git@2.66.0", domain.Package{Name: "github.com/apple/swift-nio", Version: "2.66.0", Ecosystem: domain.EcosystemSwiftPM}, true},
		{"pkg:hex/plug@1.15.0", domain.Package{Name: "plug", Version: "1.15.0", Ecosystem: domain.EcosystemHex}, true},
		{"pkg:cran/dplyr@1.1.4", domain.Package{Name: "dplyr", Version: "1.1.4", Ecosystem: domain.EcosystemCRAN}, true},
		{"pkg:swift/https%3A%2F%2F127.0.0.1%2Frepo@1.0.0", domain.Package{}, false},
		{"pkg:swift/user:token%40github.com/apple/swift-nio@2.66.0", domain.Package{}, false},
		{"pkg:deb/debian/curl@7.88.1", domain.Package{}, false},
		{"not-a-purl", domain.Package{}, false},
		{"pkg:npm/lodash", domain.Package{}, false},
		{"pkg:maven/log4j-core@2.17.1", domain.Package{}, false},
	}

	for _, tt := range tests {
		got, ok := PackageFromPURL(tt.purl)
		if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("PackageFromPURL(%q) = %+v, %v; want %+v, %v", tt.purl, got, ok, tt.want, tt.ok)
		}
	}
}

func TestPackageIdentityFromPURLAllowsVersionlessIdentifiers(t *testing.T) {
	got, ok := PackageIdentityFromPURL("pkg:pypi/django")
	want := domain.Package{Name: "django", Ecosystem: domain.EcosystemPyPI}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("PackageIdentityFromPURL(versionless) = %+v, %v; want %+v, true", got, ok, want)
	}

	if got, ok := PackageFromPURL("pkg:pypi/django"); ok || !reflect.DeepEqual(got, domain.Package{}) {
		t.Fatalf("PackageFromPURL(versionless) = %+v, %v; want zero, false", got, ok)
	}
}
