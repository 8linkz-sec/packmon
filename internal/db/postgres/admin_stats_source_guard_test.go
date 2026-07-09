package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestAdminStatsSourceDoesNotOwnUnrelatedStoreMethodGroups(t *testing.T) {
	t.Parallel()

	got := storeMethodsInSourceFile(t, "admin_stats.go")
	disallowed := map[string]string{
		"InsertScanLog":                     "scan logs",
		"GetScanLogByIdempotencyKey":        "scan logs",
		"ListRecentScans":                   "scan logs",
		"PruneScanLogs":                     "scan logs",
		"SearchPackages":                    "package search",
		"collectVulnerabilityPackageSearch": "package search",
		"collectMaliciousPackageSearch":     "package search",
		"collectReputationPackageSearch":    "package search",
		"collectLifecyclePackageSearch":     "package search",
		"collectSearchResults":              "package search",
		"FindAPIKeyByHash":                  "API key lifecycle",
		"TouchAPIKeyLastUsed":               "API key lifecycle",
		"ListAPIKeys":                       "API key lifecycle",
		"CreateAPIKey":                      "API key lifecycle",
		"CreateAPIKeyWithAudit":             "API key lifecycle",
		"RevokeAPIKey":                      "API key lifecycle",
		"RevokeAPIKeyWithAudit":             "API key lifecycle",
		"DeleteAPIKey":                      "API key lifecycle",
		"DeleteAPIKeyWithAudit":             "API key lifecycle",
		"PruneDeletedAPIKeys":               "API key lifecycle",
		"GetAdminAuth":                      "admin auth/audit",
		"UpsertAdminAuth":                   "admin auth/audit",
		"UpsertAdminAuthWithAudit":          "admin auth/audit",
		"ChangeAdminPasswordWithAudit":      "admin auth/audit",
		"InsertAdminAuditLog":               "admin auth/audit",
		"ListAdminAuditLog":                 "admin auth/audit",
		"ListAdminAuditLogPage":             "admin auth/audit",
		"PruneAdminAuditLogs":               "admin auth/audit",
		"QueueStats":                        "refresh queue",
		"OldestQueueJobs":                   "refresh queue",
		"ListQueueJobs":                     "refresh queue",
		"ListQueueJobsPage":                 "refresh queue",
		"PurgeQueue":                        "refresh queue",
		"PruneRefreshQueue":                 "refresh queue",
		"PurgeQueueWithAudit":               "refresh queue",
		"UpdateQueueJobPriority":            "refresh queue",
		"UpdateQueueJobPriorityWithAudit":   "refresh queue",
		"RetryQueueJob":                     "refresh queue",
		"RetryQueueJobWithAudit":            "refresh queue",
		"PauseQueueJob":                     "refresh queue",
		"PauseQueueJobWithAudit":            "refresh queue",
		"ResumeQueueJob":                    "refresh queue",
		"ResumeQueueJobWithAudit":           "refresh queue",
		"ClearQueue":                        "refresh queue",
		"ClearQueueWithAudit":               "refresh queue",
		"ListRecentVulnerabilities":         "dashboard stats",
		"CountScansByDay":                   "dashboard stats",
		"ScanTotals":                        "dashboard stats",
		"DashboardStats":                    "dashboard stats",
	}

	var offenders []string
	for method, group := range disallowed {
		if got[method] {
			offenders = append(offenders, method+" ("+group+")")
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("admin_stats.go still owns unrelated Store method groups: %s", strings.Join(offenders, ", "))
	}
}

func storeMethodsInSourceFile(t *testing.T, filename string) map[string]bool {
	t.Helper()

	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	methods := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		if isStoreReceiver(fn.Recv.List[0].Type) {
			methods[fn.Name.Name] = true
		}
	}
	return methods
}

func isStoreReceiver(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == "Store"
	case *ast.StarExpr:
		ident, ok := typed.X.(*ast.Ident)
		return ok && ident.Name == "Store"
	default:
		return false
	}
}
