package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestDashboardTemplatesUseSharedStatCardPartial(t *testing.T) {
	publicDashboard := readTemplateFile(t, "dashboard.html")
	adminDashboard := readTemplateFile(t, "admin", "dashboard.html")
	partial := readTemplateFile(t, "partials", "dashboard_stat_card.html")

	if !strings.Contains(partial, `{{define "dashboard-stat-card"}}`) {
		t.Fatalf("dashboard stat card partial must define dashboard-stat-card:\n%s", partial)
	}

	statLabels := []string{
		"Packages Tracked",
		"Vulnerabilities",
		"Malicious Packages",
		"Supply-chain Risks",
		"Lifecycle Findings",
	}
	statLabelKeys := []webMessageKey{
		webMessageKey("dashboard.card.packages"),
		webMessageKey("dashboard.card.vulnerabilities"),
		webMessageKey("dashboard.card.malicious"),
		webMessageKey("dashboard.card.supply_chain"),
		webMessageKey("dashboard.card.lifecycle"),
	}
	statFields := []string{
		"TotalPackages",
		"TotalVulnerabilities",
		"TotalMalicious",
		"TotalSupplyChainRisk",
		"TotalLifecycle",
	}

	for _, key := range statLabelKeys {
		if !strings.Contains(partial, `(t "`+string(key)+`")`) {
			t.Fatalf("dashboard stat card partial missing label message key %q:\n%s", key, partial)
		}
		if got := webMessage(key); got == string(key) {
			t.Fatalf("dashboard stat card message key %q missing catalog entry", key)
		}
	}
	for _, field := range statFields {
		if !strings.Contains(partial, field) {
			t.Fatalf("dashboard stat card partial missing stats field %q:\n%s", field, partial)
		}
	}

	// The public dashboard shows only the four developer-facing cards. Lifecycle,
	// scans and feed health are operator numbers and live on the admin dashboard.
	// See DESIGN.md, "Web UI -- design system and dashboard contract".
	wantCardCalls := map[string]int{
		"public dashboard": 4,
		"admin dashboard":  7,
	}

	for name, source := range map[string]string{
		"public dashboard": publicDashboard,
		"admin dashboard":  adminDashboard,
	} {
		if got := strings.Count(source, `{{template "dashboard-stat-card"`); got != wantCardCalls[name] {
			t.Fatalf("%s dashboard-stat-card calls = %d, want %d:\n%s", name, got, wantCardCalls[name], source)
		}

		for _, label := range statLabels {
			if dashboardStatLabelPattern(label).MatchString(source) {
				t.Fatalf("%s still copies shared stat label %q instead of using dashboard-stat-card:\n%s", name, label, source)
			}
		}
		for _, field := range statFields {
			if strings.Contains(source, ".Stats."+field) {
				t.Fatalf("%s still reads .Stats.%s instead of using dashboard-stat-card:\n%s", name, field, source)
			}
		}
	}
}

func readTemplateFile(t *testing.T, parts ...string) string {
	t.Helper()

	pathParts := append([]string{"templates"}, parts...)
	//nolint:gosec // G304: path built by the test itself, not from request data.
	data, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatalf("read template %s: %v", filepath.Join(pathParts...), err)
	}
	return string(data)
}

func dashboardStatLabelPattern(label string) *regexp.Regexp {
	return regexp.MustCompile(`<dt[^>]*>\s*` + regexp.QuoteMeta(label) + `\s*</dt>`)
}

// Every <dt>/<dd> of the stat card partial must sit inside a <dl> opened in the
// same {{define}} block, so the partial is self-contained valid markup for
// static HTML analysis (SonarQube Web:ItemTagNotWithinContainerTagCheck) and
// not only once a caller's <dl> wraps the rendered value.
func TestDashboardStatCardPartialNestsListItemsInsideListInEachDefine(t *testing.T) {
	partial := readTemplateFile(t, "partials", "dashboard_stat_card.html")

	defines := strings.Split(partial, `{{define "`)[1:]
	if len(defines) == 0 {
		t.Fatalf("dashboard stat card partial has no {{define}} blocks:\n%s", partial)
	}
	listTag := regexp.MustCompile(`<(/?)(dl|dt|dd)\b`)
	items := 0
	for _, block := range defines {
		name, _, _ := strings.Cut(block, `"`)
		depth := 0
		for _, match := range listTag.FindAllStringSubmatch(block, -1) {
			closing, tag := match[1] == "/", match[2]
			switch {
			case tag == "dl" && closing:
				depth--
			case tag == "dl":
				depth++
			case !closing:
				items++
				if depth < 1 {
					t.Errorf("define %q has <%s> outside a <dl> opened in the same define", name, tag)
				}
			}
		}
		if depth != 0 {
			t.Errorf("define %q leaves <dl> nesting unbalanced (depth %d)", name, depth)
		}
	}
	if items == 0 {
		t.Fatalf("dashboard stat card partial renders no <dt>/<dd> items:\n%s", partial)
	}
}

// The rendered admin stat cards keep one <dt>/<dd> pair per <dl>; only plain
// numbers carry data-local-number, the composite feed-health value does not.
func TestAdminDashboardStatCardsMarkOnlyNumericValuesForLocalFormatting(t *testing.T) {
	var out strings.Builder
	data := map[string]any{
		"ActiveNav":    "dashboard",
		"CSRFToken":    "csrf-token",
		"TotalScans7d": 7,
		"FeedsHealthy": 8,
		"FeedsTotal":   9,
		"Stats": map[string]any{
			"TotalPackages": 12, "TotalVulnerabilities": 3, "TotalMalicious": 2,
			"TotalSupplyChainRisk": 4, "TotalLifecycle": 5, "BySeverity": map[string]int{},
		},
	}
	if err := testRenderer().Render(&out, "admin/dashboard.html", data); err != nil {
		t.Fatalf("Render(admin/dashboard.html) error = %v", err)
	}
	doc, err := html.Parse(strings.NewReader(out.String()))
	if err != nil {
		t.Fatalf("parse admin dashboard HTML: %v", err)
	}

	want := map[string]struct{ text, localNumber string }{
		"Packages Tracked":   {"12", "12"},
		"Vulnerabilities":    {"3", "3"},
		"Malicious Packages": {"2", "2"},
		"Supply-chain Risks": {"4", "4"},
		"Lifecycle Findings": {"5", "5"},
		"Scans (7d)":         {"7", "7"},
		"Feeds Healthy":      {"8 / 9", ""},
	}
	seen := map[string]bool{}
	for _, list := range findElements(doc, "dl") {
		terms, values := findElements(list, "dt"), findElements(list, "dd")
		if len(terms) == 0 {
			continue
		}
		label := strings.TrimSpace(renderNodeText(terms[0]))
		card, ok := want[label]
		if !ok {
			continue // other description lists on the page, e.g. the severity breakdown
		}
		if seen[label] || len(terms) != 1 || len(values) != 1 {
			t.Fatalf("stat card %q: duplicate=%t, %d <dt> and %d <dd> in its list, want one list with one of each", label, seen[label], len(terms), len(values))
		}
		seen[label] = true
		if got := strings.TrimSpace(renderNodeText(values[0])); got != card.text {
			t.Errorf("stat card %q value = %q, want %q", label, got, card.text)
		}
		localNumber, hasLocalNumber := attr(values[0], "data-local-number")
		if hasLocalNumber != (card.localNumber != "") || localNumber != card.localNumber {
			t.Errorf("stat card %q data-local-number = %q (present %t), want %q", label, localNumber, hasLocalNumber, card.localNumber)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("admin dashboard rendered stat cards %v, want all of %d cards", seen, len(want))
	}
}
