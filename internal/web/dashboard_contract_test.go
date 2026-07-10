package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/8linkz-sec/packmon/internal/db"
)

// The public dashboard is a display-only surface. Its card set, its table
// columns, its row cap and the absence of controls are a contract, documented
// in DESIGN.md under "Web UI -- design system and dashboard contract".
//
// These assertions run against the rendered HTML, not the template source, so
// they survive class renames and only break when the structure really changes.

const dashboardRecentVulnerabilityLimit = 20

type contractStore struct {
	mockStore

	recentDays  int
	recentLimit int
}

func (s *contractStore) ListRecentVulnerabilities(_ context.Context, days, limit int) ([]db.RecentVulnerability, error) {
	s.recentDays = days
	s.recentLimit = limit

	published := time.Date(2026, time.July, 1, 12, 0, 0, 0, time.UTC)
	rows := make([]db.RecentVulnerability, 0, 25)
	for i := range 25 {
		rows = append(rows, db.RecentVulnerability{
			ID:          fmt.Sprintf("GHSA-contract-%04d", i),
			Summary:     "summary that must not be rendered on the dashboard",
			Severity:    "HIGH",
			Ecosystem:   "npm",
			Name:        fmt.Sprintf("package-%d", i),
			Affected:    "< 2.15.0",
			PublishedAt: published,
		})
	}
	// The store honours the caller's limit; the handler must ask for 20.
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	return rows, nil
}

func renderDashboardForContract(t *testing.T) (*html.Node, *contractStore) {
	t.Helper()

	store := &contractStore{}
	store.dashboardStats = &db.DashboardStatsResult{
		TotalPackages:        12,
		TotalVulnerabilities: 34,
		TotalMalicious:       5,
		TotalSupplyChainRisk: 6,
		TotalLifecycle:       7,
		BySeverity:           map[string]int{"CRITICAL": 1, "HIGH": 2},
	}

	rec := httptest.NewRecorder()
	HandleDashboard(store, testRenderer(), discardLogger())(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}

	doc, err := html.Parse(strings.NewReader(rec.Body.String()))
	if err != nil {
		t.Fatalf("parse dashboard HTML: %v", err)
	}
	return doc, store
}

func TestDashboardContractRendersFourStatCardsInOrder(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	want := []string{
		"Packages Tracked",
		"Vulnerabilities",
		"Malicious Packages",
		"Supply-chain Risks",
	}
	got := elementTexts(findElements(doc, "dt"))
	if len(got) != len(want) {
		t.Fatalf("stat cards = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stat card %d = %q, want %q (full order: %v)", i, got[i], want[i], got)
		}
	}
}

func TestDashboardContractHidesOperatorOnlyMetrics(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	body := renderNodeText(doc)
	for _, forbidden := range []string{"Lifecycle Findings", "Scans (7d)", "Feeds Healthy"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public dashboard exposes operator-only metric %q", forbidden)
		}
	}
}

func TestDashboardContractRecentTableColumnsAreFixed(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	table := findFirstElementWithAttr(doc, "table", "data-dashboard-recent-table")
	if table == nil {
		t.Fatal("dashboard is missing the recent-vulnerabilities table")
	}

	want := []string{"Package", "Version", "Ecosystem", "Severity", "Advisory", "Published"}
	got := elementTexts(findElements(table, "th"))
	if len(got) != len(want) {
		t.Fatalf("table columns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("column %d = %q, want %q (full order: %v)", i, got[i], want[i], got)
		}
	}
}

func TestDashboardContractCapsRecentRowsAtTwenty(t *testing.T) {
	doc, store := renderDashboardForContract(t)

	if store.recentLimit != dashboardRecentVulnerabilityLimit {
		t.Fatalf("ListRecentVulnerabilities limit = %d, want %d", store.recentLimit, dashboardRecentVulnerabilityLimit)
	}
	if store.recentDays != 7 {
		t.Fatalf("ListRecentVulnerabilities days = %d, want 7", store.recentDays)
	}

	table := findFirstElementWithAttr(doc, "table", "data-dashboard-recent-table")
	if table == nil {
		t.Fatal("dashboard is missing the recent-vulnerabilities table")
	}
	body := findFirstElement(table, "tbody")
	if body == nil {
		t.Fatal("recent-vulnerabilities table has no tbody")
	}
	if rows := len(findElements(body, "tr")); rows != dashboardRecentVulnerabilityLimit {
		t.Fatalf("rendered rows = %d, want %d", rows, dashboardRecentVulnerabilityLimit)
	}
}

func TestDashboardContractOmitsAdvisorySummary(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	if strings.Contains(renderNodeText(doc), "summary that must not be rendered") {
		t.Fatal("dashboard renders advisory summary text; it belongs on the package page")
	}
	if len(findElements(doc, "details")) != 0 {
		t.Fatal("dashboard renders a disclosure widget; the summary column was removed")
	}
}

// The dashboard must not act. Links navigate; buttons, forms and inputs change
// state and belong behind /admin/. The theme switcher lives in the nav, so the
// check is scoped to <main>.
func TestDashboardContractMainRegionHasNoControls(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	main := findFirstElement(doc, "main")
	if main == nil {
		t.Fatal("dashboard has no <main> region")
	}
	for _, tag := range []string{"button", "form", "input", "select", "textarea"} {
		if found := findElements(main, tag); len(found) != 0 {
			t.Fatalf("dashboard main region contains %d <%s> element(s); the dashboard is display-only", len(found), tag)
		}
	}
}

func TestDashboardContractExposesThemeSwitcherAndSkipLink(t *testing.T) {
	doc, _ := renderDashboardForContract(t)

	if findFirstElementWithAttr(doc, "div", "data-pm-theme-switcher") == nil {
		t.Fatal("layout is missing the theme switcher")
	}
	buttons := 0
	for _, node := range findElements(doc, "button") {
		if _, ok := attr(node, "data-pm-theme-set"); ok {
			buttons++
		}
	}
	if buttons != 3 {
		t.Fatalf("theme switcher buttons = %d, want 3 (light, dark, system)", buttons)
	}
	if findFirstElementWithClass(doc, "a", "skip-link") == nil {
		t.Fatal("layout is missing the skip link")
	}
}

// --- small HTML helpers -----------------------------------------------------

func attr(node *html.Node, name string) (string, bool) {
	for _, a := range node.Attr {
		if a.Key == name {
			return a.Val, true
		}
	}
	return "", false
}

func findElements(root *html.Node, tag string) []*html.Node {
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			out = append(out, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

func findFirstElement(root *html.Node, tag string) *html.Node {
	if found := findElements(root, tag); len(found) > 0 {
		return found[0]
	}
	return nil
}

func findFirstElementWithAttr(root *html.Node, tag, attrName string) *html.Node {
	for _, node := range findElements(root, tag) {
		if _, ok := attr(node, attrName); ok {
			return node
		}
	}
	return nil
}

func findFirstElementWithClass(root *html.Node, tag, class string) *html.Node {
	for _, node := range findElements(root, tag) {
		value, ok := attr(node, "class")
		if !ok {
			continue
		}
		if slices.Contains(strings.Fields(value), class) {
			return node
		}
	}
	return nil
}

func renderNodeText(root *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return sb.String()
}

func elementTexts(nodes []*html.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, strings.TrimSpace(renderNodeText(node)))
	}
	return out
}
