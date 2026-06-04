package lifecycle

import "testing"

func TestCuratedPackageMapsReturnsExpectedMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		productSlug string
		ecosystem   string
		name        string
		purlType    string
		namespace   string
		purlName    string
	}{
		{productSlug: "django", ecosystem: "pypi", name: "django", purlType: "pypi", purlName: "django"},
		{productSlug: "laravel", ecosystem: "composer", name: "laravel/framework", purlType: "composer", namespace: "laravel", purlName: "framework"},
		{productSlug: "ruby-on-rails", ecosystem: "gem", name: "rails", purlType: "gem", purlName: "rails"},
	}

	for _, tt := range tests {
		t.Run(tt.productSlug, func(t *testing.T) {
			got := CuratedPackageMaps(tt.productSlug)
			if len(got) != 1 {
				t.Fatalf("CuratedPackageMaps(%q) len = %d, want 1", tt.productSlug, len(got))
			}
			if got[0].ProductSlug != tt.productSlug || got[0].Ecosystem != tt.ecosystem || got[0].Name != tt.name ||
				got[0].PURLType != tt.purlType || got[0].PURLNamespace != tt.namespace || got[0].PURLName != tt.purlName ||
				got[0].Source != "endoflife.date" {
				t.Fatalf("CuratedPackageMaps(%q) = %+v", tt.productSlug, got[0])
			}
		})
	}
}

func TestCuratedPackageMapsReturnsCopy(t *testing.T) {
	t.Parallel()

	first := CuratedPackageMaps("django")
	first[0].Name = "mutated"

	second := CuratedPackageMaps("django")
	if second[0].Name != "django" {
		t.Fatalf("CuratedPackageMaps returned shared backing storage: %+v", second)
	}
	if got := CuratedPackageMaps("unknown"); got != nil {
		t.Fatalf("CuratedPackageMaps(unknown) = %+v, want nil", got)
	}
}
