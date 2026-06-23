package reversinglabs

import reputationpurl "github.com/8linkz-sec/packmon/internal/feed/reputation/purl"

// BuildPURL maps a Packmon package coordinate to the ReversingLabs-supported
// package URL syntax. It returns false when the package cannot be represented.
func BuildPURL(ecosystem, name, version string) (string, bool) {
	return reputationpurl.BuildReversingLabsPURL(ecosystem, name, version)
}

func SupportsPackage(ecosystem, name, version string) bool {
	return reputationpurl.SupportsReversingLabsPackage(ecosystem, name, version)
}
