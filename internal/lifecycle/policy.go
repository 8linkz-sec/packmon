// Package lifecycle centralizes Packmon lifecycle policy for endoflife.date
// release metadata, version matching, and scan finding creation.
package lifecycle

import (
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// Source identifies lifecycle metadata and findings derived from endoflife.date.
const Source = "endoflife.date"

const (
	// EOLSoonDays is the number of days before EOL that Packmon reports a
	// lifecycle warning.
	EOLSoonDays = 90
	// EOLSoonWindow is the duration before EOL covered by the lifecycle warning.
	EOLSoonWindow = time.Duration(EOLSoonDays) * 24 * time.Hour
)

const (
	// SeverityEOL is used for packages whose matched release is already EOL.
	SeverityEOL = domain.SeverityCritical
	// SeverityEOLSoon is used for packages whose matched release reaches EOL
	// within EOLSoonWindow.
	SeverityEOLSoon = domain.SeverityMedium
	// SeveritySecuritySupportOnly is used for packages whose matched release is
	// outside active support but still in security support.
	SeveritySecuritySupportOnly = domain.SeverityLow
)

const (
	// RiskTypeEOL labels lifecycle findings for releases that are already EOL.
	RiskTypeEOL = "eol"
	// RiskTypeEOLSoon labels lifecycle findings for releases approaching EOL.
	RiskTypeEOLSoon = "eol_soon"
	// RiskTypeSecuritySupportOnly labels lifecycle findings for releases that
	// receive security support only.
	RiskTypeSecuritySupportOnly = "security_support_only"
)

// PackageQuery identifies a package version for lifecycle policy evaluation.
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// Release is one product lifecycle release cycle.
type Release struct {
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
}

// ReleaseRow carries the lifecycle release metadata Packmon needs for one
// package-to-product mapping row.
type ReleaseRow struct {
	ID          string
	Ecosystem   string
	PackageName string
	ProductSlug string
	ProductName string
	Release     Release
}

// LongestMatchingReleases returns the most specific release row matching
// version for each product slug. A release cycle matches when the version is
// exactly the cycle or starts with the cycle followed by a dot; when multiple
// rows for the same product match, the longest cycle string wins. Result order
// is unspecified.
func LongestMatchingReleases(rows []ReleaseRow, version string) []ReleaseRow {
	if strings.TrimSpace(version) == "" {
		return nil
	}

	best := make(map[string]ReleaseRow)
	for _, row := range rows {
		if !cycleMatches(version, row.Release.Cycle) {
			continue
		}
		current, ok := best[row.ProductSlug]
		if !ok || len(row.Release.Cycle) > len(current.Release.Cycle) {
			best[row.ProductSlug] = row
		}
	}

	matches := make([]ReleaseRow, 0, len(best))
	for _, row := range best {
		matches = append(matches, row)
	}
	return matches
}

// FindingForRelease maps one matched release row to Packmon's canonical
// lifecycle finding policy. EOL releases produce a critical supply-chain-risk
// finding with RiskTypeEOL; releases entering EOL within EOLSoonWindow produce
// a medium lifecycle finding with RiskTypeEOLSoon; releases in security support
// only produce a low lifecycle finding with RiskTypeSecuritySupportOnly. The
// checks run in that priority order and the boolean return is false when the
// release does not create a finding.
func FindingForRelease(pkg PackageQuery, row ReleaseRow, now time.Time) (domain.Finding, bool) {
	release := row.Release
	if release.IsEOL || dateOnOrBefore(release.EOLFrom, now) {
		return buildFinding(pkg, row, domain.FindingTypeSupplyChainRisk, SeverityEOL, RiskTypeEOL, "is end-of-life"), true
	}
	if dateWithin(release.EOLFrom, now, EOLSoonWindow) {
		return buildFinding(pkg, row, domain.FindingTypeLifecycle, SeverityEOLSoon, RiskTypeEOLSoon, "reaches end-of-life soon"), true
	}
	if release.IsEOAS || dateOnOrBefore(release.EOASFrom, now) {
		return buildFinding(pkg, row, domain.FindingTypeLifecycle, SeveritySecuritySupportOnly, RiskTypeSecuritySupportOnly, "is in security support only"), true
	}
	return domain.Finding{}, false
}

func cycleMatches(version, cycle string) bool {
	version = strings.TrimSpace(version)
	cycle = strings.TrimSpace(cycle)
	if version == "" || cycle == "" {
		return false
	}
	return version == cycle || strings.HasPrefix(version, cycle+".")
}

func buildFinding(pkg PackageQuery, row ReleaseRow, typ domain.FindingType, severity domain.Severity, riskType, phrase string) domain.Finding {
	productName := strings.TrimSpace(row.ProductName)
	if productName == "" {
		productName = row.ProductSlug
	}
	url := fmt.Sprintf("https://endoflife.date/%s", row.ProductSlug)
	title := fmt.Sprintf("%s %s %s", productName, row.Release.Cycle, phrase)

	return domain.Finding{
		Name:       pkg.Name,
		Version:    pkg.Version,
		Ecosystem:  domain.Ecosystem(pkg.Ecosystem),
		Type:       typ,
		Severity:   severity,
		AdvisoryID: fmt.Sprintf("endoflife:%s:%s:%s", row.ProductSlug, row.Release.Cycle, riskType),
		Title:      title,
		URL:        url,
		Resources: []domain.ResourceLink{
			{Label: Source, URL: url},
		},
		RiskType: riskType,
		Source:   Source,
	}
}

func dateOnOrBefore(date *time.Time, now time.Time) bool {
	return date != nil && !date.After(now)
}

func dateWithin(date *time.Time, now time.Time, window time.Duration) bool {
	return date != nil && date.After(now) && !date.After(now.Add(window))
}
