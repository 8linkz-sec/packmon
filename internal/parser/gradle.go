package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// GradleParser parses gradle.lockfile files. Gradle uses Maven repositories,
// so the ecosystem is EcosystemMaven.
type GradleParser struct{}

func NewGradleParser() *GradleParser {
	return &GradleParser{}
}

func (p *GradleParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "gradle.lockfile")
}

func (p *GradleParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemMaven
}

func (p *GradleParser) Parse(r io.Reader) ([]domain.Package, error) {
	scanner := newLineScanner(r)

	type pkgKey struct {
		name    string
		version string
	}
	seen := make(map[pkgKey]int)

	var (
		packages []domain.Package
		errs     []string
		lineNum  int
	)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines.
		if line == "" {
			continue
		}

		// Skip comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Skip empty configuration lines like "empty=".
		if strings.HasSuffix(line, "=") && !strings.Contains(line, ":") {
			continue
		}

		// Expected format: group:artifact:version=variant(s)
		// Split on "=" first to separate the coordinate from the configuration list.
		coordinate, configurations, _ := strings.Cut(line, "=")

		// Split coordinate into group:artifact:version.
		parts := strings.SplitN(coordinate, ":", 3)
		if len(parts) != 3 {
			errs = append(errs, fmt.Sprintf("line %d: expected group:artifact:version, got %q", lineNum, coordinate))
			continue
		}

		group := strings.TrimSpace(parts[0])
		artifact := strings.TrimSpace(parts[1])
		version := strings.TrimSpace(parts[2])

		if group == "" || artifact == "" {
			errs = append(errs, fmt.Sprintf("line %d: empty group or artifact in %q", lineNum, coordinate))
			continue
		}
		if version == "" {
			errs = append(errs, fmt.Sprintf("line %d: missing version for %s:%s", lineNum, group, artifact))
			continue
		}

		name := group + ":" + artifact
		key := pkgKey{name: strings.ToLower(name), version: version}
		dev := gradleConfigurationsDev(configurations)
		if idx, exists := seen[key]; exists {
			if packages[idx].Dev && !dev {
				packages[idx].Dev = false
			}
			continue
		}
		seen[key] = len(packages)

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemMaven,
			Dev:       dev,
		})
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("gradle: reading input: %w", err)
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("gradle: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func gradleConfigurationsDev(configurations string) bool {
	configurations = strings.TrimSpace(configurations)
	if configurations == "" {
		return false
	}
	hasDev := false
	for _, raw := range strings.Split(configurations, ",") {
		config := strings.ToLower(strings.TrimSpace(raw))
		if config == "" {
			continue
		}
		if strings.Contains(config, "test") || strings.Contains(config, "dev") {
			hasDev = true
			continue
		}
		return false
	}
	return hasDev
}
