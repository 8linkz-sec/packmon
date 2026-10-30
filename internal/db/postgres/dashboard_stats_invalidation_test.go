package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestDashboardStatsMutationMethodsInvalidateCache(t *testing.T) {
	t.Parallel()

	methodsByFile := map[string][]string{
		"vulnerabilities.go": {
			"UpsertVulnerability", "importVulnerabilityFeed", "DeleteVulnerability", "DeleteVulnerabilityForSource",
		},
		"malicious.go": {
			"UpsertMaliciousFinding", "importMaliciousFeed", "DeleteMaliciousFinding", "DeleteMaliciousFindingForSource",
			"DeleteMaliciousFindingsNotInSource", "PruneMaliciousFindingsForSourceUpdatedBefore",
		},
		"malicious_snapshot.go":       {"replaceMaliciousFindingsSnapshot"},
		"reputation.go":               {"UpsertPackageReputation"},
		"lifecycle.go":                {"ReplaceLifecycleProducts"},
		"manual_advisories.go":        {"UpsertManualAdvisory", "UpsertManualAdvisoryWithAudit", "DeleteManualAdvisory", "DeleteManualAdvisoryWithAudit"},
		"vulnerability_enrichment.go": {"PropagateSeverityViaAliases", "UpdateSeverityByCVE"},
		"package_name_repair.go":      {"RepairCaseInsensitivePackageNames", "RepairCaseInsensitivePackageNamesWithAudit"},
		"ghsa_repair.go":              {"RepairGHSAAffectedPackages"},
	}

	for filename, methods := range methodsByFile {
		filename, methods := filename, methods
		t.Run(filename, func(t *testing.T) {
			t.Parallel()
			file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", filename, err)
			}
			found := make(map[string]bool, len(methods))
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				for _, want := range methods {
					if fn.Name.Name != want {
						continue
					}
					ast.Inspect(fn.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok {
							return true
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						if ok && selector.Sel.Name == "invalidateDashboardStats" {
							found[want] = true
						}
						return true
					})
				}
			}
			for _, method := range methods {
				if !found[method] {
					t.Errorf("%s.%s does not invalidate dashboard stats after its successful mutation", filename, method)
				}
			}
		})
	}
}
