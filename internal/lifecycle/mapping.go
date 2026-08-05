package lifecycle

// PackageMap links a package identity to an endoflife.date product slug.
type PackageMap struct {
	Ecosystem     string
	Name          string
	ProductSlug   string
	PURLType      string
	PURLNamespace string
	PURLName      string
	Source        string
}

// CuratedPackageMaps returns conservative package-to-product mappings for
// products whose endoflife.date records may not yet expose PURL identifiers.
func CuratedPackageMaps(productSlug string) []PackageMap {
	maps := curatedPackageMaps[productSlug]
	if len(maps) == 0 {
		return nil
	}
	out := make([]PackageMap, len(maps))
	copy(out, maps)
	for i := range out {
		out[i].ProductSlug = productSlug
		if out[i].Source == "" {
			out[i].Source = "endoflife.date"
		}
	}
	return out
}

var curatedPackageMaps = map[string][]PackageMap{
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
