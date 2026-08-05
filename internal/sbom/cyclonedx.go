package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// MaxSizeBytes is the maximum accepted size for any supported SBOM input.
// CycloneDX JSON, CycloneDX XML, and SPDX JSON documents are capped at 100 MiB
// before parsing.
const MaxSizeBytes = 100 << 20

const maxSBOMSize = MaxSizeBytes

const (
	maxCycloneDXComponents           = 20000
	maxCycloneDXDependencyEntries    = 20000
	maxCycloneDXDependencyEdges      = 100000
	maxCycloneDXRootDependencies     = 5000
	maxCycloneDXViaRootsPerComponent = 32
	maxCycloneDXViaStates            = maxCycloneDXDependencyEntries * maxCycloneDXViaRootsPerComponent
)

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
	XMLName      xml.Name                 `xml:"bom"`
	Metadata     cyclonedxXMLMetadata     `xml:"metadata"`
	Components   []cyclonedxXMLComponent  `xml:"components>component"`
	Dependencies []cyclonedxXMLDependency `xml:"dependencies>dependency"`
}

type cyclonedxXMLMetadata struct {
	Component cyclonedxXMLComponent `xml:"component"`
}

type cyclonedxXMLComponent struct {
	Type    string `xml:"type,attr"`
	BOMRef  string `xml:"bom-ref,attr"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
	PURL    string `xml:"purl"`
}

type cyclonedxXMLDependency struct {
	Ref       string                      `xml:"ref,attr"`
	DependsOn []cyclonedxXMLDependencyRef `xml:"dependency"`
}

type cyclonedxXMLDependencyRef struct {
	Ref string `xml:"ref,attr"`
}

func parseCycloneDX(data []byte) (*ParseResult, error) {
	if IsCycloneDXJSON(data) {
		var doc cyclonedxJSON
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
		}
		return importCycloneDXJSON(doc)
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
				BOMRef:  c.BOMRef,
				PURL:    c.PURL,
			})
		}
		dependencies := cyclonedxXMLDependencies(doc.Dependencies)
		if err := validateCycloneDXWorkLimits(len(components), doc.Metadata.Component.BOMRef, dependencies); err != nil {
			return nil, err
		}
		result := importCycloneDXComponents(components)
		if err := applyCycloneDXDependencyMetadata(result.Packages, doc.Metadata.Component.BOMRef, dependencies); err != nil {
			return nil, err
		}
		return result, nil
	}

	return nil, fmt.Errorf("unsupported CycloneDX format")
}

func cyclonedxXMLDependencies(items []cyclonedxXMLDependency) []cyclonedxDependency {
	if len(items) == 0 {
		return nil
	}
	out := make([]cyclonedxDependency, 0, len(items))
	for _, item := range items {
		dep := cyclonedxDependency{Ref: item.Ref}
		for _, child := range item.DependsOn {
			dep.DependsOn = append(dep.DependsOn, child.Ref)
		}
		out = append(out, dep)
	}
	return out
}

func importCycloneDXJSON(doc cyclonedxJSON) (*ParseResult, error) {
	if err := validateCycloneDXWorkLimits(len(doc.Components), doc.Metadata.Component.BOMRef, doc.Dependencies); err != nil {
		return nil, err
	}
	result := importCycloneDXComponents(doc.Components)
	if err := applyCycloneDXDependencyMetadata(result.Packages, doc.Metadata.Component.BOMRef, doc.Dependencies); err != nil {
		return nil, err
	}
	return result, nil
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

func applyCycloneDXDependencyMetadata(packages []Package, rootRef string, dependencies []cyclonedxDependency) error {
	if len(packages) == 0 || len(dependencies) == 0 {
		return nil
	}

	refToIndex := buildCycloneDXRefIndex(packages)
	edges := buildCycloneDXDependencyEdges(dependencies)
	rootRef = strings.TrimSpace(rootRef)
	markCycloneDXDirectDependencies(packages, refToIndex, edges, rootRef)
	return attachCycloneDXDependencyMetadata(packages, refToIndex, edges, rootRef)
}

func validateCycloneDXWorkLimits(componentCount int, rootRef string, dependencies []cyclonedxDependency) error {
	if componentCount > maxCycloneDXComponents {
		return fmt.Errorf("CycloneDX component count %d exceeds maximum of %d", componentCount, maxCycloneDXComponents)
	}
	if len(dependencies) > maxCycloneDXDependencyEntries {
		return fmt.Errorf("CycloneDX dependency entry count %d exceeds maximum of %d", len(dependencies), maxCycloneDXDependencyEntries)
	}

	rootRef = strings.TrimSpace(rootRef)
	edgeCount := 0
	rootDependencyCount := 0
	for _, dep := range dependencies {
		ref := strings.TrimSpace(dep.Ref)
		for _, childRef := range dep.DependsOn {
			if strings.TrimSpace(childRef) == "" {
				continue
			}
			edgeCount++
			if edgeCount > maxCycloneDXDependencyEdges {
				return fmt.Errorf("CycloneDX dependency edge count exceeds maximum of %d", maxCycloneDXDependencyEdges)
			}
			if rootRef != "" && ref == rootRef {
				rootDependencyCount++
				if rootDependencyCount > maxCycloneDXRootDependencies {
					return fmt.Errorf("CycloneDX root dependency count exceeds maximum of %d", maxCycloneDXRootDependencies)
				}
			}
		}
	}
	return nil
}

func buildCycloneDXRefIndex(packages []Package) map[string]int {
	refToIndex := make(map[string]int, len(packages))
	for i, item := range packages {
		ref := strings.TrimSpace(item.BOMRef)
		if ref == "" {
			continue
		}
		refToIndex[ref] = i
	}
	return refToIndex
}

func buildCycloneDXDependencyEdges(dependencies []cyclonedxDependency) map[string][]string {
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
	return edges
}

func markCycloneDXDirectDependencies(packages []Package, refToIndex map[string]int, edges map[string][]string, rootRef string) {
	rootRef = strings.TrimSpace(rootRef)
	if rootRef == "" {
		return
	}
	for _, directRef := range edges[rootRef] {
		if idx, ok := refToIndex[directRef]; ok {
			packages[idx].Package.Direct = true
		}
	}
}

func attachCycloneDXDependencyMetadata(packages []Package, refToIndex map[string]int, edges map[string][]string, rootRef string) error {
	rootRef = strings.TrimSpace(rootRef)
	if rootRef != "" {
		if err := attachCycloneDXRootVia(packages, refToIndex, edges, rootRef); err != nil {
			return err
		}
	}
	attachCycloneDXPackageParents(packages, refToIndex, edges)
	return nil
}

func attachCycloneDXPackageParents(packages []Package, refToIndex map[string]int, edges map[string][]string) {
	parentsByChildRef := make(map[string][]domain.PackageParent)
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
			parentsByChildRef[childRef] = append(parentsByChildRef[childRef], parent)
		}
	}

	for childRef, parents := range parentsByChildRef {
		childIdx, childIsPackage := refToIndex[childRef]
		if !childIsPackage {
			continue
		}
		child := &packages[childIdx].Package
		child.Parents = domain.MergePackageParents(child.Parents, parents)
		if !child.Direct {
			child.Indirect = true
		}
	}
}

type cycloneDXViaRoot struct {
	name      string
	directRef string
}

type cycloneDXViaBudget struct {
	states int
}

func (b *cycloneDXViaBudget) addState() error {
	b.states++
	if b.states > maxCycloneDXViaStates {
		return fmt.Errorf("CycloneDX dependency via-state count exceeds maximum of %d", maxCycloneDXViaStates)
	}
	return nil
}

func attachCycloneDXRootVia(packages []Package, refToIndex map[string]int, edges map[string][]string, rootRef string) error {
	viaByRef := make(map[string]map[cycloneDXViaRoot]struct{})
	queue := make([]string, 0)
	budget := &cycloneDXViaBudget{}

	for _, root := range cycloneDXDirectViaRoots(packages, refToIndex, edges[rootRef]) {
		for _, childRef := range edges[root.directRef] {
			if changed, err := addCycloneDXViaRoot(viaByRef, childRef, root, budget); err != nil {
				return err
			} else if changed {
				queue = append(queue, childRef)
			}
		}
	}

	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		roots := viaByRef[ref]
		for _, childRef := range edges[ref] {
			if changed, err := mergeCycloneDXViaRoots(viaByRef, childRef, roots, budget); err != nil {
				return err
			} else if changed {
				queue = append(queue, childRef)
			}
		}
	}

	for ref, roots := range viaByRef {
		idx, ok := refToIndex[ref]
		if !ok {
			continue
		}
		pkg := &packages[idx].Package
		pkg.Indirect = true
		pkg.Via = domain.MergePackageStringSet(pkg.Via, cycloneDXViaRootValues(roots))
	}
	return nil
}

func cycloneDXDirectViaRoots(packages []Package, refToIndex map[string]int, directRefs []string) []cycloneDXViaRoot {
	roots := make([]cycloneDXViaRoot, 0, len(directRefs))
	seen := make(map[cycloneDXViaRoot]struct{}, len(directRefs))
	for _, directRef := range directRefs {
		directRef = strings.TrimSpace(directRef)
		idx, ok := refToIndex[directRef]
		if !ok {
			continue
		}
		rootName := strings.TrimSpace(packages[idx].Package.Name)
		if rootName == "" {
			continue
		}
		root := cycloneDXViaRoot{name: rootName, directRef: directRef}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	sort.Slice(roots, func(i, j int) bool {
		return cycloneDXViaRootLess(roots[i], roots[j])
	})
	return roots
}

func addCycloneDXViaRoot(viaByRef map[string]map[cycloneDXViaRoot]struct{}, ref string, root cycloneDXViaRoot, budget *cycloneDXViaBudget) (bool, error) {
	ref = strings.TrimSpace(ref)
	root.name = strings.TrimSpace(root.name)
	root.directRef = strings.TrimSpace(root.directRef)
	if ref == "" || root.name == "" || root.directRef == "" || ref == root.directRef {
		return false, nil
	}
	roots := viaByRef[ref]
	if roots == nil {
		roots = make(map[cycloneDXViaRoot]struct{}, 1)
		viaByRef[ref] = roots
	}
	if _, ok := roots[root]; ok {
		return false, nil
	}
	if len(roots) >= maxCycloneDXViaRootsPerComponent {
		return false, nil
	}
	if budget != nil {
		if err := budget.addState(); err != nil {
			return false, err
		}
	}
	roots[root] = struct{}{}
	return true, nil
}

func mergeCycloneDXViaRoots(viaByRef map[string]map[cycloneDXViaRoot]struct{}, ref string, roots map[cycloneDXViaRoot]struct{}, budget *cycloneDXViaBudget) (bool, error) {
	changed := false
	for _, root := range cycloneDXSortedViaRoots(roots) {
		added, err := addCycloneDXViaRoot(viaByRef, ref, root, budget)
		if err != nil {
			return false, err
		}
		if added {
			changed = true
		}
	}
	return changed, nil
}

func cycloneDXSortedViaRoots(roots map[cycloneDXViaRoot]struct{}) []cycloneDXViaRoot {
	out := make([]cycloneDXViaRoot, 0, len(roots))
	for root := range roots {
		out = append(out, root)
	}
	sort.Slice(out, func(i, j int) bool {
		return cycloneDXViaRootLess(out[i], out[j])
	})
	return out
}

func cycloneDXViaRootLess(left, right cycloneDXViaRoot) bool {
	if left.name != right.name {
		return left.name < right.name
	}
	return left.directRef < right.directRef
}

func cycloneDXViaRootValues(roots map[cycloneDXViaRoot]struct{}) []string {
	names := make(map[string]struct{}, len(roots))
	for root := range roots {
		if root.name != "" {
			names[root.name] = struct{}{}
		}
	}
	values := make([]string, 0, len(names))
	for name := range names {
		values = append(values, name)
	}
	return values
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
