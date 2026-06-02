package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const maxSBOMSize = 100 << 20

type cyclonedxJSON struct {
	BOMFormat  string               `json:"bomFormat"`
	Components []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cyclonedxXML struct {
	XMLName    xml.Name                `xml:"bom"`
	Components []cyclonedxXMLComponent `xml:"components>component"`
}

type cyclonedxXMLComponent struct {
	Type    string `xml:"type,attr"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
	PURL    string `xml:"purl"`
}

// ParseCycloneDX parses CycloneDX JSON or XML and imports supported components
// with usable package-url identities.
func ParseCycloneDX(r io.Reader) (*ParseResult, error) {
	data, err := readSBOM(r)
	if err != nil {
		return nil, err
	}

	if IsCycloneDXJSON(data) {
		var doc cyclonedxJSON
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
		}
		return importCycloneDXComponents(doc.Components), nil
	}

	if IsCycloneDXXML(data) {
		var doc cyclonedxXML
		if err := xml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse CycloneDX XML: %w", err)
		}
		components := make([]cyclonedxComponent, 0, len(doc.Components))
		for _, c := range doc.Components {
			components = append(components, cyclonedxComponent(c))
		}
		return importCycloneDXComponents(components), nil
	}

	return nil, fmt.Errorf("unsupported CycloneDX format")
}

// IsCycloneDXJSON reports whether data looks like CycloneDX JSON.
func IsCycloneDXJSON(data []byte) bool {
	var header struct {
		BOMFormat string `json:"bomFormat"`
	}
	if json.Unmarshal(data, &header) != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(header.BOMFormat), "CycloneDX")
}

// IsCycloneDXXML reports whether data looks like CycloneDX XML.
func IsCycloneDXXML(data []byte) bool {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return false
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start.Name.Local == "bom"
		}
	}
}

func importCycloneDXComponents(components []cyclonedxComponent) *ParseResult {
	result := &ParseResult{Packages: []Package{}, Skipped: []SkippedComponent{}}
	for _, c := range components {
		name := strings.TrimSpace(c.Name)
		if !supportedCycloneDXComponentType(c.Type) {
			result.Skipped = append(result.Skipped, SkippedComponent{Name: name, Reason: "unsupported component type"})
			continue
		}
		purl := strings.TrimSpace(c.PURL)
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
			Source:  "cyclonedx",
		})
	}
	return result
}

func supportedCycloneDXComponentType(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "library", "framework", "application":
		return true
	default:
		return false
	}
}

func readSBOM(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSBOMSize+1))
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	if len(data) > maxSBOMSize {
		return nil, fmt.Errorf("SBOM exceeds maximum size of %d bytes", maxSBOMSize)
	}
	return data, nil
}
