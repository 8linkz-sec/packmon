package domain

import (
	"reflect"
	"testing"
)

func TestMergePackageMetadata(t *testing.T) {
	t.Parallel()

	dst := Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: EcosystemNPM,
		Dev:       true,
		Indirect:  true,
		Peer:      true,
		Via:       []string{" tailwindcss ", ""},
		Parents: []PackageParent{
			{Name: " tailwindcss ", Version: "3.4.17", Ecosystem: EcosystemNPM},
			{Name: "", Version: "ignored", Ecosystem: EcosystemNPM},
		},
		SourceRefs: []string{" https://registry.npmjs.org/postcss/-/postcss-8.5.8.tgz "},
	}
	MergePackageMetadata(&dst, Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: EcosystemNPM,
		Direct:    true,
		Optional:  true,
		Via:       []string{"other", "tailwindcss"},
		Parents: []PackageParent{
			{Name: "other", Version: "1.0.0", Ecosystem: EcosystemNPM},
			{Name: "tailwindcss", Version: "3.4.17", Ecosystem: EcosystemNPM},
		},
		SourceRefs: []string{"https://registry.npmjs.org/postcss/-/postcss-8.5.8.tgz", "https://mirror.example/postcss.tgz"},
	})

	if dst.Dev || !dst.Direct || !dst.Indirect || !dst.Optional || !dst.Peer {
		t.Fatalf("merged flags = %+v, want production direct+indirect optional peer", dst)
	}
	if want := []string{"other", "tailwindcss"}; !reflect.DeepEqual(dst.Via, want) {
		t.Fatalf("Via = %#v, want %#v", dst.Via, want)
	}
	if want := []PackageParent{
		{Name: "other", Version: "1.0.0", Ecosystem: EcosystemNPM},
		{Name: "tailwindcss", Version: "3.4.17", Ecosystem: EcosystemNPM},
	}; !reflect.DeepEqual(dst.Parents, want) {
		t.Fatalf("Parents = %#v, want %#v", dst.Parents, want)
	}
	if want := []string{"https://mirror.example/postcss.tgz", "https://registry.npmjs.org/postcss/-/postcss-8.5.8.tgz"}; !reflect.DeepEqual(dst.SourceRefs, want) {
		t.Fatalf("SourceRefs = %#v, want %#v", dst.SourceRefs, want)
	}
}

func TestMergePackageMetadataKeepsDevWhenOnlyDev(t *testing.T) {
	t.Parallel()

	dst := Package{Dev: true}
	MergePackageMetadata(&dst, Package{Dev: true})
	if !dst.Dev {
		t.Fatalf("Dev = false, want true when only dev metadata is merged")
	}
}

func TestMergePackageStringSetNil(t *testing.T) {
	t.Parallel()

	if got := MergePackageStringSet(nil, nil); got != nil {
		t.Fatalf("MergePackageStringSet(nil, nil) = %#v, want nil", got)
	}
}
