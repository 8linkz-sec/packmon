package purl

import "strings"

const (
	MaxPackageNameLength    = 512
	MaxPackageVersionLength = 256
)

// BuildReversingLabsPURL maps a Packmon package coordinate to the
// ReversingLabs-supported package URL syntax. It returns false when the package
// cannot be represented safely in the reputation cache or upstream request.
func BuildReversingLabsPURL(ecosystem, name, version string) (string, bool) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || len(name) > MaxPackageNameLength || len(version) > MaxPackageVersionLength {
		return "", false
	}

	escapedVersion := escapeComponent(version)
	switch ecosystem {
	case "pypi", "gem", "nuget":
		return "pkg:" + ecosystem + "/" + escapeComponent(name) + "@" + escapedVersion, true
	case "npm":
		if strings.HasPrefix(name, "@") {
			scopeAndName := strings.TrimPrefix(name, "@")
			scope, pkg, ok := strings.Cut(scopeAndName, "/")
			if ok {
				scope = strings.TrimSpace(scope)
				pkg = strings.TrimSpace(pkg)
				if scope == "" || pkg == "" {
					return "", false
				}
				return "pkg:npm/%40" + escapeComponent(scope) + "/" + escapeComponent(pkg) + "@" + escapedVersion, true
			}
			if strings.TrimSpace(scopeAndName) == "" {
				return "", false
			}
			return "pkg:npm/%40" + escapeComponent(scopeAndName) + "@" + escapedVersion, true
		}
		return "pkg:npm/" + escapeComponent(name) + "@" + escapedVersion, true
	case "maven":
		groupID, artifactID, ok := strings.Cut(name, ":")
		if !ok {
			return "", false
		}
		groupID = strings.TrimSpace(groupID)
		artifactID = strings.TrimSpace(artifactID)
		if groupID == "" || artifactID == "" {
			return "", false
		}
		return "pkg:maven/" + escapeComponent(groupID) + "/" + escapeComponent(artifactID) + "@" + escapedVersion, true
	default:
		return "", false
	}
}

func SupportsReversingLabsPackage(ecosystem, name, version string) bool {
	_, ok := BuildReversingLabsPURL(ecosystem, name, version)
	return ok
}

func escapeComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isUnreserved(c) {
			out.WriteByte(c)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hex[c>>4])
		out.WriteByte(hex[c&0x0f])
	}
	return out.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '.' ||
		c == '_' ||
		c == '~'
}
