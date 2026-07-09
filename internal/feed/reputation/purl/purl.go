package purl

import "github.com/8linkz-sec/packmon/internal/feed/reputationpurl"

const (
	MaxPackageNameLength    = reputationpurl.MaxPackageNameLength
	MaxPackageVersionLength = reputationpurl.MaxPackageVersionLength
)

// BuildReversingLabsPURL maps a Packmon package coordinate to the
// ReversingLabs-supported package URL syntax.
//
// Deprecated: use internal/feed/reputationpurl.BuildReversingLabsPURL.
func BuildReversingLabsPURL(ecosystem, name, version string) (string, bool) {
	return reputationpurl.BuildReversingLabsPURL(ecosystem, name, version)
}

// SupportsReversingLabsPackage reports whether the coordinate can be mapped to
// a ReversingLabs package URL.
//
// Deprecated: use internal/feed/reputationpurl.SupportsReversingLabsPackage.
func SupportsReversingLabsPackage(ecosystem, name, version string) bool {
	return reputationpurl.SupportsReversingLabsPackage(ecosystem, name, version)
}
