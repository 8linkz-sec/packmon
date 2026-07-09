package web

import (
	"strings"
	"testing"
)

func TestPackageRiskFindingTablesUseSharedPartial(t *testing.T) {
	t.Parallel()

	page := readTextFile(t, "templates", "package.html")
	partial := readTextFile(t, "templates", "partials", "package_risk_finding_table.html")

	if got := strings.Count(page, `{{template "package-risk-finding-table"`); got != 3 {
		t.Fatalf("package.html risk table partial calls = %d, want 3", got)
	}
	for _, want := range []string{
		`{{template "package-risk-finding-table" dict "Findings" .Malicious "AriaLabel" (t "package.malicious.table") "RowClass" "border-b border-gray-100 bg-red-50 hover:bg-red-100"}}`,
		`{{template "package-risk-finding-table" dict "Findings" .SupplyChain "AriaLabel" (t "package.supply_chain.table") "RowClass" "border-b border-gray-100 bg-amber-50 hover:bg-amber-100"}}`,
		`{{template "package-risk-finding-table" dict "Findings" .Lifecycle "AriaLabel" (t "package.lifecycle.table") "RowClass" "border-b border-gray-100 hover:bg-gray-50"}}`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("package.html missing shared risk table call %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `<th class="px-5 py-2">Risk Type</th>`) {
		t.Fatalf("package.html still contains copied risk table structure")
	}

	if got := strings.Count(partial, `{{t "package.table.risk_type"}}`); got != 1 {
		t.Fatalf("package risk table partial Risk Type headers = %d, want 1", got)
	}
	for _, want := range []string{
		`{{define "package-risk-finding-table"}}`,
		`aria-label="{{.AriaLabel}}"`,
		`{{range .Findings}}`,
		`<tr class="{{$.RowClass}}">`,
		`{{template "risk-type-cell" .}}`,
		`{{template "finding-resources" .}}`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("package risk table partial missing %q:\n%s", want, partial)
		}
	}
}
