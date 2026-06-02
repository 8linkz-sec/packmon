package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type spdxJSON struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// ParseSPDXJSON parses SPDX JSON package entries with package-url external refs.
func ParseSPDXJSON(r io.Reader) (*ParseResult, error) {
	data, err := readSBOM(r)
	if err != nil {
		return nil, err
	}
	if !IsSPDXJSON(data) {
		return nil, fmt.Errorf("unsupported SPDX JSON format")
	}

	var doc spdxJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX JSON: %w", err)
	}

	result := &ParseResult{Packages: []Package{}, Skipped: []SkippedComponent{}}
	for _, entry := range doc.Packages {
		name := strings.TrimSpace(entry.Name)
		if invalidSPDXValue(name) {
			result.Skipped = append(result.Skipped, SkippedComponent{Name: name, Reason: "invalid package name"})
			continue
		}

		purl := spdxPackagePURL(entry)
		if purl == "" {
			result.Skipped = append(result.Skipped, SkippedComponent{Name: name, Reason: "missing purl"})
			continue
		}

		pkg, ok := PackageFromPURL(purl)
		if !ok {
			result.Skipped = append(result.Skipped, SkippedComponent{Name: name, Reason: "unsupported or versionless purl"})
			continue
		}
		result.Packages = append(result.Packages, Package{
			Package: pkg,
			PURL:    purl,
			Source:  "spdx",
		})
	}
	return result, nil
}

// IsSPDXJSON reports whether data looks like SPDX JSON.
func IsSPDXJSON(data []byte) bool {
	var header struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(data, &header) != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(header.SPDXVersion), "SPDX-")
}

func spdxPackagePURL(pkg spdxPackage) string {
	for _, ref := range pkg.ExternalRefs {
		if !strings.EqualFold(strings.TrimSpace(ref.ReferenceType), "purl") {
			continue
		}
		locator := strings.TrimSpace(ref.ReferenceLocator)
		if locator != "" {
			return locator
		}
	}
	return ""
}

func invalidSPDXValue(raw string) bool {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "NOASSERTION", "NONE":
		return true
	default:
		return false
	}
}
