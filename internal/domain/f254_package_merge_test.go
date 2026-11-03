package domain

import (
	"reflect"
	"testing"
)

func TestF254MergePackageMetadataFillsWhitespaceDeclaredVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  string
		src  string
		want string
	}{
		{name: "trimmed value", dst: " \t ", src: " v5.1.0 ", want: "v5.1.0"},
		{name: "blank value", dst: "\r\n", src: " \t ", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := Package{DeclaredVersion: tc.dst}
			MergePackageMetadata(&dst, Package{DeclaredVersion: tc.src})
			if dst.DeclaredVersion != tc.want {
				t.Fatalf("DeclaredVersion = %q, want %q", dst.DeclaredVersion, tc.want)
			}
		})
	}
}

func TestF254MergePackageParentsBlankDedupeAndOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  []PackageParent
		right []PackageParent
		want  []PackageParent
	}{
		{
			name:  "blank names from both inputs",
			left:  []PackageParent{{Name: "  ", Version: "1", Ecosystem: EcosystemNPM}},
			right: []PackageParent{{Name: "\t", Version: "2", Ecosystem: EcosystemPyPI}},
			want:  nil,
		},
		{
			name: "full identity and every sort key",
			left: []PackageParent{
				{Name: " same ", Version: " 2 ", Ecosystem: EcosystemNPM},
				{Name: "same", Version: "1", Ecosystem: EcosystemPyPI},
				{Name: "alpha", Version: "1", Ecosystem: EcosystemNPM},
				{Name: "zeta", Version: "9", Ecosystem: EcosystemGo},
			},
			right: []PackageParent{
				{Name: "same", Version: "2", Ecosystem: EcosystemNPM},
				{Name: "same", Version: "1", Ecosystem: EcosystemNPM},
			},
			want: []PackageParent{
				{Name: "zeta", Version: "9", Ecosystem: EcosystemGo},
				{Name: "alpha", Version: "1", Ecosystem: EcosystemNPM},
				{Name: "same", Version: "1", Ecosystem: EcosystemNPM},
				{Name: "same", Version: "2", Ecosystem: EcosystemNPM},
				{Name: "same", Version: "1", Ecosystem: EcosystemPyPI},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MergePackageParents(tc.left, tc.right)
			if tc.want == nil {
				if len(got) != 0 {
					t.Fatalf("MergePackageParents() = %#v, want no parents", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MergePackageParents() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
