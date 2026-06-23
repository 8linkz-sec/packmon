package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// MavenParser parses pom.xml files (Maven/Java ecosystem).
type MavenParser struct{}

// mavenProject represents the top-level <project> element of a pom.xml file.
type mavenProject struct {
	XMLName              xml.Name           `xml:"project"`
	Dependencies         []mavenDependency  `xml:"dependencies>dependency"`
	DependencyManagement mavenDepManagement `xml:"dependencyManagement"`
	Repositories         []mavenRepository  `xml:"repositories>repository"`
}

// mavenDepManagement represents the <dependencyManagement> element.
type mavenDepManagement struct {
	Dependencies []mavenDependency `xml:"dependencies>dependency"`
}

// mavenDependency represents a single <dependency> element.
type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type mavenRepository struct {
	URL string `xml:"url"`
}

func NewMavenParser() *MavenParser {
	return &MavenParser{}
}

func (p *MavenParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "pom.xml")
}

func (p *MavenParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemMaven
}

func (p *MavenParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("maven: reading input: %w", err)
	}

	var project mavenProject
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("maven: parsing XML: %w", err)
	}

	// Collect dependencies from both <dependencies> and <dependencyManagement>.
	allDeps := make([]mavenDependency, 0, len(project.Dependencies)+len(project.DependencyManagement.Dependencies))
	allDeps = append(allDeps, project.Dependencies...)
	allDeps = append(allDeps, project.DependencyManagement.Dependencies...)

	type pkgKey struct {
		name    string
		version string
	}
	seen := make(map[pkgKey]struct{})

	var (
		packages []domain.Package
		errs     []string
	)
	repositoryRefs := make([]string, 0, len(project.Repositories))
	for _, repository := range project.Repositories {
		repositoryRefs = append(repositoryRefs, repository.URL)
	}

	for i, dep := range allDeps {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			errs = append(errs, fmt.Sprintf("dependency %d: missing groupId or artifactId", i))
			continue
		}

		isDev := strings.EqualFold(strings.TrimSpace(dep.Scope), "test")

		version := strings.TrimSpace(dep.Version)

		// Skip dependencies with no version at all.
		if version == "" {
			errs = append(errs, fmt.Sprintf("dependency %d: missing version", i))
			continue
		}

		// Skip dependencies where the version is a Maven property placeholder
		// like ${some.version} -- these cannot be resolved without the full
		// POM hierarchy.
		if strings.HasPrefix(version, "${") && strings.HasSuffix(version, "}") {
			continue
		}

		name := dep.GroupID + ":" + dep.ArtifactID
		key := pkgKey{name: name, version: version}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		packages = append(packages, domain.Package{
			Name:       name,
			Version:    version,
			Ecosystem:  domain.EcosystemMaven,
			Dev:        isDev,
			SourceRefs: cleanSourceRefs(repositoryRefs...),
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("maven: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}
