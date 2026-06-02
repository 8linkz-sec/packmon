package lifecycle

import "github.com/8linkz/packmon/internal/db"

// CuratedPackageMaps returns conservative package-to-product mappings for
// products whose endoflife.date records may not yet expose PURL identifiers.
func CuratedPackageMaps(productSlug string) []db.LifecyclePackageMap {
	maps := curatedPackageMaps[productSlug]
	if len(maps) == 0 {
		return nil
	}
	out := make([]db.LifecyclePackageMap, len(maps))
	copy(out, maps)
	for i := range out {
		out[i].ProductSlug = productSlug
		if out[i].Source == "" {
			out[i].Source = "endoflife.date"
		}
	}
	return out
}

var curatedPackageMaps = map[string][]db.LifecyclePackageMap{
	"django": {
		{Ecosystem: "pypi", Name: "django", PURLType: "pypi", PURLName: "django"},
	},
	"laravel": {
		{Ecosystem: "composer", Name: "laravel/framework", PURLType: "composer", PURLNamespace: "laravel", PURLName: "framework"},
	},
	"ruby-on-rails": {
		{Ecosystem: "gem", Name: "rails", PURLType: "gem", PURLName: "rails"},
	},
}
