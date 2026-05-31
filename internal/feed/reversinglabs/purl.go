package reversinglabs

import "strings"

// BuildPURL maps a Packmon package coordinate to the ReversingLabs-supported
// package URL syntax. It returns false when the package cannot be represented.
func BuildPURL(ecosystem, name, version string) (string, bool) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return "", false
	}

	switch ecosystem {
	case "pypi", "gem", "nuget":
		return "pkg:" + ecosystem + "/" + name + "@" + version, true
	case "npm":
		if strings.HasPrefix(name, "@") {
			name = "%40" + strings.TrimPrefix(name, "@")
		}
		return "pkg:npm/" + name + "@" + version, true
	case "maven":
		parts := strings.SplitN(name, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", false
		}
		groupID := strings.TrimSpace(parts[0])
		artifactID := strings.TrimSpace(parts[1])
		return "pkg:maven/" + groupID + "/" + artifactID + "@" + version, true
	default:
		return "", false
	}
}

func SupportsPackage(ecosystem, name, version string) bool {
	_, ok := BuildPURL(ecosystem, name, version)
	return ok
}
