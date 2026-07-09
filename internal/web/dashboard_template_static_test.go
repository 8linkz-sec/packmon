package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

	for name, source := range map[string]string{
		"public dashboard": publicDashboard,
		"admin dashboard":  adminDashboard,
	} {
		if got := strings.Count(source, `{{template "dashboard-stat-card"`); got != len(statLabelKeys) {
			t.Fatalf("%s dashboard-stat-card calls = %d, want %d:\n%s", name, got, len(statLabelKeys), source)
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
	data, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatalf("read template %s: %v", filepath.Join(pathParts...), err)
	}
	return string(data)
}

func dashboardStatLabelPattern(label string) *regexp.Regexp {
	return regexp.MustCompile(`<dt[^>]*>\s*` + regexp.QuoteMeta(label) + `\s*</dt>`)
}
