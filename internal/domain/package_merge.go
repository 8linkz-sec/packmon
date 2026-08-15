package domain

import (
	"sort"
	"strings"
)

// MergePackageMetadata merges package provenance and relationship metadata
// for duplicate package identities. Production scope wins over dev scope.
func MergePackageMetadata(dst *Package, src Package) {
	if dst == nil {
		return
	}
	if dst.Dev && !src.Dev {
		dst.Dev = false
	}
	dst.Direct = dst.Direct || src.Direct
	dst.Indirect = dst.Indirect || src.Indirect
	dst.Optional = dst.Optional || src.Optional
	dst.Peer = dst.Peer || src.Peer
	dst.Via = MergePackageStringSet(dst.Via, src.Via)
	dst.Parents = MergePackageParents(dst.Parents, src.Parents)
	dst.SourceRefs = MergePackageStringSet(dst.SourceRefs, src.SourceRefs)
	if strings.TrimSpace(dst.DeclaredVersion) == "" {
		dst.DeclaredVersion = strings.TrimSpace(src.DeclaredVersion)
	}
}

// MergePackageStringSet trims, de-duplicates, and sorts package metadata
// string sets such as Via and SourceRefs.
func MergePackageStringSet(left, right []string) []string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// MergePackageParents trims, de-duplicates, and sorts immediate package
// parents used by graph-aware update reporting.
func MergePackageParents(left, right []PackageParent) []PackageParent {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	type parentKey struct {
		name, version string
		ecosystem     Ecosystem
	}
	seen := make(map[parentKey]PackageParent, len(left)+len(right))
	add := func(parent PackageParent) {
		parent.Name = strings.TrimSpace(parent.Name)
		parent.Version = strings.TrimSpace(parent.Version)
		if parent.Name == "" {
			return
		}
		seen[parentKey{parent.Name, parent.Version, parent.Ecosystem}] = parent
	}
	for _, parent := range left {
		add(parent)
	}
	for _, parent := range right {
		add(parent)
	}
	out := make([]PackageParent, 0, len(seen))
	for _, parent := range seen {
		out = append(out, parent)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
