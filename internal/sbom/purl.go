package sbom

import (
	"net/url"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	pkgid "github.com/8linkz-sec/packmon/internal/packageid"
)

// PackageFromPURL maps a package-url string into Packmon's canonical package
// identity. Unsupported PURL types and versionless PURLs return false.
func PackageFromPURL(raw string) (domain.Package, bool) {
	pkg, ok := packageFromPURL(raw, true)
	return pkg, ok
}

// PackageIdentityFromPURL maps a package-url string into a Packmon package
// identity without requiring a version. This is useful for feed identifiers
// such as endoflife.date PURLs, while SBOM component imports remain versioned
// through PackageFromPURL.
func PackageIdentityFromPURL(raw string) (domain.Package, bool) {
	pkg, ok := packageFromPURL(raw, false)
	if ok {
		pkg.Version = ""
	}
	return pkg, ok
}

func packageFromPURL(raw string, requireVersion bool) (domain.Package, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "pkg:") {
		return domain.Package{}, false
	}

	body := strings.TrimPrefix(raw, "pkg:")
	body = strings.TrimSpace(body)
	if body == "" {
		return domain.Package{}, false
	}

	identity := body
	if idx := strings.IndexAny(identity, "?#"); idx >= 0 {
		identity = identity[:idx]
	}

	versionIdx := strings.LastIndex(identity, "@")
	if versionIdx < 0 {
		if requireVersion {
			return domain.Package{}, false
		}
		versionIdx = len(identity)
	}

	beforeVersion := identity[:versionIdx]
	version := ""
	if versionIdx < len(identity) {
		decodedVersion, ok := decodePURLVersion(identity[versionIdx+1:])
		if !ok {
			return domain.Package{}, false
		}
		version = decodedVersion
	}
	if requireVersion && strings.TrimSpace(version) == "" {
		return domain.Package{}, false
	}

	typeName, path, ok := strings.Cut(beforeVersion, "/")
	if !ok || strings.TrimSpace(typeName) == "" || strings.TrimSpace(path) == "" {
		return domain.Package{}, false
	}

	purlType := strings.ToLower(strings.TrimSpace(typeName))
	segments, ok := decodePURLPath(path)
	if !ok || len(segments) == 0 {
		return domain.Package{}, false
	}

	name, ecosystem, ok := packageNameFromPURLPath(purlType, segments)
	if !ok || strings.TrimSpace(name) == "" {
		return domain.Package{}, false
	}

	return domain.Package{
		Name:      pkgid.NormalizeName(string(ecosystem), name),
		Version:   version,
		Ecosystem: ecosystem,
	}, true
}

func stripPURLSuffix(version string) string {
	version = strings.TrimSpace(version)
	if idx := strings.IndexAny(version, "?#"); idx >= 0 {
		version = version[:idx]
	}
	return strings.TrimSpace(version)
}

func decodePURLVersion(version string) (string, bool) {
	version = stripPURLSuffix(version)
	decoded, err := url.PathUnescape(version)
	if err != nil {
		return "", false
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return "", false
	}
	return decoded, true
}

func decodePURLPath(path string) ([]string, bool) {
	rawSegments := strings.Split(path, "/")
	segments := make([]string, 0, len(rawSegments))
	for _, raw := range rawSegments {
		if raw == "" {
			return nil, false
		}
		decoded, err := url.PathUnescape(raw)
		if err != nil || strings.TrimSpace(decoded) == "" {
			return nil, false
		}
		segments = append(segments, decoded)
	}
	return segments, true
}

func packageNameFromPURLPath(purlType string, segments []string) (string, domain.Ecosystem, bool) {
	switch purlType {
	case "npm":
		return joinSegments(segments), domain.EcosystemNPM, true
	case "pypi":
		return lastSegment(segments), domain.EcosystemPyPI, len(segments) == 1
	case "maven":
		if len(segments) != 2 {
			return "", "", false
		}
		return segments[0] + ":" + segments[1], domain.EcosystemMaven, true
	case "golang":
		return joinSegments(segments), domain.EcosystemGo, true
	case "cargo":
		return lastSegment(segments), domain.EcosystemCargo, len(segments) == 1
	case "nuget":
		return lastSegment(segments), domain.EcosystemNuGet, len(segments) == 1
	case "composer":
		if len(segments) != 2 {
			return "", "", false
		}
		return segments[0] + "/" + segments[1], domain.EcosystemComposer, true
	case "gem":
		return lastSegment(segments), domain.EcosystemGem, len(segments) == 1
	case "pub":
		return lastSegment(segments), domain.EcosystemPub, len(segments) == 1
	case "cocoapods":
		return lastSegment(segments), domain.EcosystemCocoaPods, len(segments) == 1
	case "swift":
		name, ok := swiftPURLPackageName(segments)
		return name, domain.EcosystemSwiftPM, ok
	case "hex":
		return lastSegment(segments), domain.EcosystemHex, len(segments) == 1
	case "cran":
		return lastSegment(segments), domain.EcosystemCRAN, len(segments) == 1
	default:
		return "", "", false
	}
}

func swiftPURLPackageName(segments []string) (string, bool) {
	if len(segments) < 3 {
		return "", false
	}
	clean := make([]string, 0, len(segments))
	for i, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" ||
			segment == "." ||
			segment == ".." ||
			strings.Contains(segment, "://") ||
			strings.ContainsAny(segment, " \t\r\n\x00\\@:") {
			return "", false
		}
		if i == 0 {
			segment = strings.ToLower(segment)
		}
		clean = append(clean, segment)
	}
	last := clean[len(clean)-1]
	if strings.HasSuffix(strings.ToLower(last), ".git") {
		last = last[:len(last)-len(".git")]
		if last == "" {
			return "", false
		}
		clean[len(clean)-1] = last
	}
	return strings.Join(clean, "/"), true
}

func joinSegments(segments []string) string {
	return strings.Join(segments, "/")
}

func lastSegment(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}
