package findinglinks

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type Link struct {
	Label string
	URL   string
}

type VulnerabilityReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type resourceCandidate struct {
	link  domain.ResourceLink
	score int
}

var ghsaIDPattern = regexp.MustCompile(`GHSA-[A-Za-z0-9-]+`)

func AdvisoryLabel(f domain.Finding) string {
	if strings.TrimSpace(f.AdvisoryID) != "" {
		return f.AdvisoryID
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "MALWARE"
	case domain.FindingTypeSupplyChainRisk:
		if strings.EqualFold(strings.TrimSpace(f.RiskType), "malware_history") {
			return "MALWARE-HISTORY"
		}
		return "SUPPLY-CHAIN"
	case domain.FindingTypeLifecycle:
		return "LIFECYCLE"
	default:
		return ""
	}
}

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

func SecureSoftwarePackageURL(ecosystem domain.Ecosystem, name string) string {
	ecosystemValue := strings.TrimSpace(string(ecosystem))
	name = strings.TrimSpace(name)
	if ecosystemValue == "" || name == "" {
		return ""
	}
	return "https://secure.software/" + url.PathEscape(ecosystemValue) + "/packages/" + url.PathEscape(name)
}

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

func ClassifyVulnerabilityResource(advisoryID string, ref VulnerabilityReference) (domain.ResourceLink, int, bool) {
	if strings.TrimSpace(ref.URL) == "" {
		return domain.ResourceLink{}, 0, false
	}
	if !ShouldStoreVulnerabilityReference(ref.URL) {
		return domain.ResourceLink{}, 0, false
	}
	if strings.EqualFold(strings.TrimSpace(ref.Type), "PACKAGE") {
		return domain.ResourceLink{}, 0, false
	}
	if strings.EqualFold(strings.TrimSpace(ref.Type), "VULNCHECK") {
		return domain.ResourceLink{Label: "VulnCheck", URL: ref.URL}, ResourceScore(advisoryID, "VulnCheck"), true
	}

	parsed, err := url.Parse(ref.URL)
	if err != nil {
		return domain.ResourceLink{}, 0, false
	}

	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www.")
	if host == "" {
		return domain.ResourceLink{}, 0, false
	}
	if isGenericReferenceLandingPage(host, parsed) {
		return domain.ResourceLink{}, 0, false
	}
	path := strings.ToLower(parsed.EscapedPath())

	switch {
	case IsBlockedReferenceHost(host):
		return domain.ResourceLink{}, 0, false
	case host == "github.com" && strings.Contains(path, "/security/advisories/"):
		score := 10
		if ghsaID := ghsaIDPattern.FindString(ref.URL); strings.EqualFold(ghsaID, advisoryID) {
			score = 0
		}
		return domain.ResourceLink{Label: "GHSA", URL: ref.URL}, score, true
	case host == "nvd.nist.gov":
		return domain.ResourceLink{Label: "NVD", URL: ref.URL}, ResourceScore(advisoryID, "NVD"), true
	case host == "rustsec.org" && strings.Contains(path, "/advisories/"):
		return domain.ResourceLink{Label: "RustSec", URL: ref.URL}, ResourceScore(advisoryID, "RustSec"), true
	case host == "osv.dev":
		return domain.ResourceLink{Label: "OSV", URL: ref.URL}, ResourceScore(advisoryID, "OSV"), true
	case host == "huntr.com" || host == "huntr.dev":
		return domain.ResourceLink{Label: "Huntr", URL: ref.URL}, ResourceScore(advisoryID, "Huntr"), true
	case host == "cve.org" || host == "cve.mitre.org":
		return domain.ResourceLink{Label: "CVE", URL: ref.URL}, ResourceScore(advisoryID, "CVE"), true
	case host == "github.com":
		return domain.ResourceLink{Label: "GitHub", URL: ref.URL}, ResourceScore(advisoryID, "GitHub"), true
	default:
		return domain.ResourceLink{Label: host, URL: ref.URL}, ResourceScore(advisoryID, host), true
	}
}

func ResourceLinkFromURL(raw string) domain.ResourceLink {
	link, _, ok := ClassifyVulnerabilityResource("", VulnerabilityReference{URL: raw})
	if !ok {
		return domain.ResourceLink{}
	}
	return link
}

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

func IsBlockedReferenceHost(host string) bool {
	switch host {
	case "packetstormsecurity.com", "packetstorm.news":
		return true
	default:
		return false
	}
}

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
