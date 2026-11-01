package postgres

import (
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestMaliciousBatchVersionsKeepsEmptyVersion pins FindMaliciousBatch (which
// groups its requested versions with packageVersionsByKey) to the
// FindMalicious contract: an empty requested version asks for every active
// finding of the package, so it must survive next to concrete versions of the
// same package instead of being dropped.
func TestMaliciousBatchVersionsKeepsEmptyVersion(t *testing.T) {
	t.Parallel()

	got := packageVersionsByKey([]db.PackageQuery{
		{Ecosystem: "npm", Name: "pkg", Version: ""},
		{Ecosystem: "npm", Name: "pkg", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "pkg", Version: "2.0.0"},
		{Ecosystem: "pypi", Name: "My.Pkg", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "my-pkg", Version: ""},
		{Ecosystem: "nuget", Name: "Only.Empty", Version: ""},
		{Ecosystem: "nuget", Name: "only.empty", Version: ""},
	})

	want := map[packageLookupKey][]string{
		{ecosystem: "npm", name: "pkg"}:          {"", "2.0.0"},
		{ecosystem: "pypi", name: "my-pkg"}:      {"1.0.0", ""},
		{ecosystem: "nuget", name: "only.empty"}: {""},
	}
	if len(got) != len(want) {
		t.Fatalf("packageVersionsByKey() = %v, want %v", got, want)
	}
	for key, versions := range want {
		if !slices.Equal(got[key], versions) {
			t.Fatalf("packageVersionsByKey()[%v] = %q, want %q", key, got[key], versions)
		}
	}
}
