package findinglinks

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// Link is a clickable advisory or resource link prepared for CLI and web
// rendering.
type Link struct {
	Label string
	URL   string
}

// VulnerabilityReference is one raw advisory reference entry as stored from
// vulnerability feed metadata.
type VulnerabilityReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type resourceCandidate struct {
	link  domain.ResourceLink
	score int
}

type vulnerabilityResourceContext struct {
	advisoryID     string
	ref            VulnerabilityReference
	safeURL        string
	host           string
	path           string
	parsed         *url.URL
	genericLanding bool
}

type vulnerabilityResourceRule struct {
	label               string
	allowGenericLanding bool
	matches             func(vulnerabilityResourceContext) bool
	score               func(vulnerabilityResourceContext) int
}

var ghsaIDPattern = regexp.MustCompile(`GHSA-[A-Za-z0-9-]+`)

var vulnerabilityResourceRules = []vulnerabilityResourceRule{
	{
		label:               "VulnCheck",
		allowGenericLanding: true,
		matches: func(ctx vulnerabilityResourceContext) bool {
			return strings.EqualFold(strings.TrimSpace(ctx.ref.Type), "VULNCHECK")
		},
	},
	{
		label: "GHSA",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "github.com" && strings.Contains(ctx.path, "/security/advisories/")
		},
		score: func(ctx vulnerabilityResourceContext) int {
			if ghsaID := ghsaIDPattern.FindString(ctx.safeURL); strings.EqualFold(ghsaID, ctx.advisoryID) {
				return 0
			}
			return 10
		},
	},
	{
		label: "NVD",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "nvd.nist.gov"
		},
	},
	{
		label: "RustSec",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "rustsec.org" && strings.Contains(ctx.path, "/advisories/")
		},
	},
	{
		label: "OSV",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "osv.dev"
		},
	},
	{
		label: "Huntr",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "huntr.com" || ctx.host == "huntr.dev"
		},
	},
	{
		label: "CVE",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "cve.org" || ctx.host == "cve.mitre.org"
		},
	},
	{
		label: "GitHub",
		matches: func(ctx vulnerabilityResourceContext) bool {
			return ctx.host == "github.com"
		},
	},
}

// AdvisoryLabel returns the concise label shown for a finding's primary
// advisory. It prefers the advisory ID and falls back to stable type labels for
// malware, supply-chain risk, and lifecycle findings.
func AdvisoryLabel(f domain.Finding) string {
	if strings.TrimSpace(f.AdvisoryID) != "" {
		return f.AdvisoryID
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "MALWARE"
	case domain.FindingTypeSupplyChainRisk:
		if strings.EqualFold(strings.TrimSpace(f.RiskType), domain.RiskTypeMalwareHistory) {
			return "MALWARE-HISTORY"
		}
		return "SUPPLY-CHAIN"
	case domain.FindingTypeLifecycle:
		return "LIFECYCLE"
	default:
		return ""
	}
}

// AdvisoryURL returns the preferred safe advisory URL for a finding.
// Canonical GHSA, CVE/NVD, and RustSec links outrank stored feed URLs; package
// reputation findings prefer the secure.software package page when available.
func AdvisoryURL(f domain.Finding) string {
	advisoryID := strings.TrimSpace(f.AdvisoryID)
	advisoryIDUpper := strings.ToUpper(advisoryID)
	switch {
	case strings.HasPrefix(advisoryIDUpper, "GHSA-"):
		return "https://github.com/advisories/" + advisoryID
	case strings.HasPrefix(advisoryIDUpper, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + advisoryID
	case strings.HasPrefix(advisoryIDUpper, "RUSTSEC-"):
		return "https://rustsec.org/advisories/" + advisoryID + ".html"
	}

	if strings.HasPrefix(strings.ToLower(advisoryID), "reversinglabs:") ||
		strings.EqualFold(strings.TrimSpace(f.Source), "reversinglabs") {
		if u := SecureSoftwarePackageURL(f.Ecosystem, f.Name); u != "" {
			return u
		}
	}

	if u := SafeHTTPURL(f.URL); u != "" {
		return u
	}
	for _, resource := range f.Resources {
		if u := SafeHTTPURL(resource.URL); u != "" {
			return u
		}
	}
	return ""
}

// FindingLinks splits a finding's stored URLs into clickable safe HTTP(S) links
// and plain-text values that should be displayed but not linked.
func FindingLinks(f domain.Finding) (links []Link, plain []string) {
	add := func(label, raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if safe := SafeHTTPURL(raw); safe != "" {
			lbl := strings.TrimSpace(label)
			if lbl == "" {
				if parsed, err := url.Parse(safe); err == nil {
					lbl = parsed.Host + parsed.EscapedPath()
				}
			}
			links = append(links, Link{Label: lbl, URL: safe})
			return
		}
		plain = append(plain, raw)
	}
	add("", f.URL)
	for _, resource := range f.Resources {
		add(resource.Label, resource.URL)
	}
	return links, plain
}

// SafeHTTPURL returns raw when it is an absolute HTTP(S) URL with a host.
// Non-HTTP(S), relative, malformed, or hostless values are rejected.
func SafeHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.Hostname() == "" {
		return ""
	}
	return raw
}

// SecureSoftwarePackageURL returns the ReversingLabs secure.software package
// page for an ecosystem/name pair, or empty when either value is missing.
func SecureSoftwarePackageURL(ecosystem domain.Ecosystem, name string) string {
	ecosystemValue := strings.TrimSpace(string(ecosystem))
	name = strings.TrimSpace(name)
	if ecosystemValue == "" || name == "" {
		return ""
	}
	return "https://secure.software/" + url.PathEscape(ecosystemValue) + "/packages/" + url.PathEscape(name)
}

// ResourceLinksFromVulnerabilityReferences parses feed reference JSON and
// returns ranked, deduplicated resource links. Canonical advisory links are
// seeded first, blocked hosts and generic landing pages are dropped, and lower
// scores win when multiple URLs map to the same label.
func ResourceLinksFromVulnerabilityReferences(advisoryID, raw string) []domain.ResourceLink {
	selected := make(map[string]resourceCandidate)
	if link, score, ok := CanonicalVulnerabilityResource(advisoryID); ok {
		selected[link.Label] = resourceCandidate{link: link, score: score}
	}

	if strings.TrimSpace(raw) == "" {
		return sortedResourceCandidates(selected)
	}

	var refs []VulnerabilityReference
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return sortedResourceCandidates(selected)
	}

	for _, ref := range refs {
		link, score, ok := ClassifyVulnerabilityResource(advisoryID, ref)
		if !ok {
			continue
		}
		existing, exists := selected[link.Label]
		if !exists || score < existing.score {
			selected[link.Label] = resourceCandidate{link: link, score: score}
		}
	}

	return sortedResourceCandidates(selected)
}

func sortedResourceCandidates(selected map[string]resourceCandidate) []domain.ResourceLink {
	if len(selected) == 0 {
		return nil
	}
	labels := make([]string, 0, len(selected))
	for label := range selected {
		labels = append(labels, label)
	}

	sort.Slice(labels, func(i, j int) bool {
		left := selected[labels[i]]
		right := selected[labels[j]]
		if left.score != right.score {
			return left.score < right.score
		}
		return labels[i] < labels[j]
	})

	out := make([]domain.ResourceLink, 0, len(labels))
	for _, label := range labels {
		out = append(out, selected[label].link)
	}
	return out
}

// CanonicalVulnerabilityResource returns the canonical GHSA, RustSec, or NVD
// resource link for known advisory ID prefixes.
func CanonicalVulnerabilityResource(advisoryID string) (domain.ResourceLink, int, bool) {
	switch {
	case strings.HasPrefix(advisoryID, "GHSA-"):
		return domain.ResourceLink{Label: "GHSA", URL: "https://github.com/advisories/" + advisoryID}, 5, true
	case strings.HasPrefix(advisoryID, "RUSTSEC-"):
		return domain.ResourceLink{Label: "RustSec", URL: "https://rustsec.org/advisories/" + advisoryID + ".html"}, 5, true
	case strings.HasPrefix(advisoryID, "CVE-"):
		return domain.ResourceLink{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + advisoryID}, 5, true
	default:
		return domain.ResourceLink{}, 0, false
	}
}

// ClassifyVulnerabilityResource converts one feed reference into a display
// resource link and ranking score. It accepts only safe HTTP(S) URLs, rejects
// blocked hosts, package-only references, and generic landing pages, and assigns
// provider labels such as GHSA, NVD, RustSec, OSV, Huntr, CVE, or GitHub.
func ClassifyVulnerabilityResource(advisoryID string, ref VulnerabilityReference) (domain.ResourceLink, int, bool) {
	return classifyVulnerabilityResourceWithRules(advisoryID, ref, vulnerabilityResourceRules)
}

func classifyVulnerabilityResourceWithRules(advisoryID string, ref VulnerabilityReference, rules []vulnerabilityResourceRule) (domain.ResourceLink, int, bool) {
	safeURL := SafeHTTPURL(ref.URL)
	if safeURL == "" {
		return domain.ResourceLink{}, 0, false
	}
	if !ShouldStoreVulnerabilityReference(safeURL) {
		return domain.ResourceLink{}, 0, false
	}
	if strings.EqualFold(strings.TrimSpace(ref.Type), "PACKAGE") {
		return domain.ResourceLink{}, 0, false
	}

	parsed, err := url.Parse(safeURL)
	if err != nil {
		return domain.ResourceLink{}, 0, false
	}

	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www.")
	if host == "" {
		return domain.ResourceLink{}, 0, false
	}
	if IsBlockedReferenceHost(host) {
		return domain.ResourceLink{}, 0, false
	}

	ctx := vulnerabilityResourceContext{
		advisoryID:     advisoryID,
		ref:            ref,
		safeURL:        safeURL,
		host:           host,
		path:           strings.ToLower(parsed.EscapedPath()),
		parsed:         parsed,
		genericLanding: isGenericReferenceLandingPage(host, parsed),
	}
	if link, score, ok := matchVulnerabilityResourceRule(ctx, rules); ok {
		return link, score, true
	}
	if ctx.genericLanding {
		return domain.ResourceLink{}, 0, false
	}

	return domain.ResourceLink{Label: host, URL: safeURL}, ResourceScore(advisoryID, host), true
}

func matchVulnerabilityResourceRule(ctx vulnerabilityResourceContext, rules []vulnerabilityResourceRule) (domain.ResourceLink, int, bool) {
	for _, rule := range rules {
		if rule.matches == nil {
			continue
		}
		if ctx.genericLanding && !rule.allowGenericLanding {
			continue
		}
		if !rule.matches(ctx) {
			continue
		}

		score := ResourceScore(ctx.advisoryID, rule.label)
		if rule.score != nil {
			score = rule.score(ctx)
		}
		return domain.ResourceLink{Label: rule.label, URL: ctx.safeURL}, score, true
	}

	return domain.ResourceLink{}, 0, false
}

// ResourceLinkFromURL classifies a single URL without an advisory preference.
func ResourceLinkFromURL(raw string) domain.ResourceLink {
	link, _, ok := ClassifyVulnerabilityResource("", VulnerabilityReference{URL: raw})
	if !ok {
		return domain.ResourceLink{}
	}
	return link
}

// FirstSafeHTTPURLFromJSON returns the first safe HTTP(S) URL in a JSON string
// array, or empty for invalid JSON or unsupported URL values.
func FirstSafeHTTPURLFromJSON(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var urls []string
	if err := json.Unmarshal([]byte(raw), &urls); err != nil {
		return ""
	}
	for _, candidate := range urls {
		if u := SafeHTTPURL(candidate); u != "" {
			return u
		}
	}
	return ""
}

// ShouldStoreVulnerabilityReference reports whether a raw vulnerability
// reference should be persisted for later display. It blocks known noisy or
// unsafe reference hosts while leaving unparsable values available for
// conservative caller handling.
func ShouldStoreVulnerabilityReference(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}
	if containsBlockedReferenceValue(rawURL) {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}

	return !IsBlockedReferenceHost(strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www."))
}

func containsBlockedReferenceValue(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.Contains(lower, "packetstormsecurity.com") || strings.Contains(lower, "packetstorm.news")
}

func isGenericReferenceLandingPage(host string, parsed *url.URL) bool {
	path := strings.Trim(strings.ToLower(parsed.EscapedPath()), "/")
	if path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
		return true
	}

	if host == "github.com" && parsed.RawQuery == "" && parsed.Fragment == "" {
		segments := strings.Split(path, "/")
		if len(segments) == 2 && segments[0] != "" && segments[1] != "" && segments[0] != "advisories" {
			return true
		}
	}

	return false
}

// IsBlockedReferenceHost reports whether host is excluded from stored or
// clickable vulnerability resource links.
func IsBlockedReferenceHost(host string) bool {
	switch host {
	case "packetstormsecurity.com", "packetstorm.news":
		return true
	default:
		return false
	}
}

// ResourceScore ranks resource labels for a given advisory ID. Lower scores are
// better; the canonical provider for the advisory prefix receives the strongest
// preference, followed by common vulnerability databases and source links.
func ResourceScore(advisoryID, label string) int {
	preferred := ""
	switch {
	case strings.HasPrefix(advisoryID, "GHSA-"):
		preferred = "GHSA"
	case strings.HasPrefix(advisoryID, "RUSTSEC-"):
		preferred = "RustSec"
	case strings.HasPrefix(advisoryID, "CVE-"):
		preferred = "NVD"
	}

	if label == preferred {
		return 0
	}

	switch label {
	case "GHSA":
		return 10
	case "NVD":
		return 20
	case "RustSec":
		return 30
	case "OSV":
		return 40
	case "Huntr":
		return 50
	case "CVE":
		return 60
	case "GitHub":
		return 70
	default:
		return 100
	}
}
