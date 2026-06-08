package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

const maxSBOMSize = 100 << 20

type cyclonedxJSON struct {
	BOMFormat    string                `json:"bomFormat"`
	Metadata     cyclonedxMetadata     `json:"metadata"`
	Components   []cyclonedxComponent  `json:"components"`
	Dependencies []cyclonedxDependency `json:"dependencies"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BOMRef  string `json:"bom-ref"`
	PURL    string `json:"purl"`
}

type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
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
	return parseCycloneDX(data)
}

func parseCycloneDX(data []byte) (*ParseResult, error) {
	if IsCycloneDXJSON(data) {
		var doc cyclonedxJSON
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
		}
		return importCycloneDXJSON(doc), nil
	}

	if IsCycloneDXXML(data) {
		var doc cyclonedxXML
		if err := xml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse CycloneDX XML: %w", err)
		}
		components := make([]cyclonedxComponent, 0, len(doc.Components))
		for _, c := range doc.Components {
			components = append(components, cyclonedxComponent{
				Type:    c.Type,
				Name:    c.Name,
				Version: c.Version,
				PURL:    c.PURL,
			})
		}
		return importCycloneDXComponents(components), nil
	}

	return nil, fmt.Errorf("unsupported CycloneDX format")
}

func importCycloneDXJSON(doc cyclonedxJSON) *ParseResult {
	result := importCycloneDXComponents(doc.Components)
	applyCycloneDXDependencyMetadata(result.Packages, doc.Metadata.Component.BOMRef, doc.Dependencies)
	return result
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
	decoder := xml.NewDecoder(bytes.NewReader(data))
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
			BOMRef:  strings.TrimSpace(c.BOMRef),
		})
	}
	return result
}

func applyCycloneDXDependencyMetadata(packages []Package, rootRef string, dependencies []cyclonedxDependency) {
	if len(packages) == 0 || len(dependencies) == 0 {
		return
	}

	refToIndex := make(map[string]int, len(packages))
	for i, item := range packages {
		ref := strings.TrimSpace(item.BOMRef)
		if ref == "" {
			continue
		}
		refToIndex[ref] = i
	}

	edges := make(map[string][]string, len(dependencies))
	for _, dep := range dependencies {
		ref := strings.TrimSpace(dep.Ref)
		if ref == "" {
			continue
		}
		for _, childRef := range dep.DependsOn {
			childRef = strings.TrimSpace(childRef)
			if childRef != "" {
				edges[ref] = append(edges[ref], childRef)
			}
		}
	}

	rootRef = strings.TrimSpace(rootRef)
	if rootRef != "" {
		for _, directRef := range edges[rootRef] {
			if idx, ok := refToIndex[directRef]; ok {
				packages[idx].Package.Direct = true
			}
			if idx, ok := refToIndex[directRef]; ok {
				rootName := packages[idx].Package.Name
				applyCycloneDXRootVia(packages, refToIndex, edges, directRef, rootName)
			}
		}
	}

	for parentRef, childRefs := range edges {
		parentIdx, parentIsPackage := refToIndex[parentRef]
		if !parentIsPackage {
			continue
		}
		parentPkg := packages[parentIdx].Package
		parent := domain.PackageParent{
			Name:      parentPkg.Name,
			Version:   parentPkg.Version,
			Ecosystem: parentPkg.Ecosystem,
		}
		for _, childRef := range childRefs {
			childIdx, childIsPackage := refToIndex[childRef]
			if !childIsPackage || childIdx == parentIdx {
				continue
			}
			child := &packages[childIdx].Package
			child.Parents = mergeSBOMPackageParents(child.Parents, []domain.PackageParent{parent})
			if !child.Direct {
				child.Indirect = true
			}
		}
	}
}

func applyCycloneDXRootVia(packages []Package, refToIndex map[string]int, edges map[string][]string, rootChildRef, rootName string) {
	rootName = strings.TrimSpace(rootName)
	if rootName == "" {
		return
	}
	seen := map[string]struct{}{rootChildRef: {}}
	queue := append([]string(nil), edges[rootChildRef]...)
	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		if idx, ok := refToIndex[ref]; ok {
			pkg := &packages[idx].Package
			pkg.Indirect = true
			pkg.Via = mergeSBOMStringSet(pkg.Via, []string{rootName})
		}
		queue = append(queue, edges[ref]...)
	}
}

func mergeSBOMStringSet(left, right []string) []string {
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

func mergeSBOMPackageParents(left, right []domain.PackageParent) []domain.PackageParent {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	type parentKey struct {
		name, version string
		ecosystem     domain.Ecosystem
	}
	seen := make(map[parentKey]domain.PackageParent, len(left)+len(right))
	add := func(parent domain.PackageParent) {
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
	out := make([]domain.PackageParent, 0, len(seen))
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
