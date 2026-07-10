package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/testutil"
)

func TestAutoFallbackWarning(t *testing.T) {
	t.Parallel()

	age := 5
	cases := []struct {
		name   string
		mode   scanner.Mode
		result *domain.ScanResult
		want   string
	}{
		{"auto fallback with age", scanner.ModeAuto, &domain.ScanResult{Mode: "local", DBAgeDays: &age}, "warning: remote server unreachable, scanned against local database (5 days old)"},
		{"auto fallback without age", scanner.ModeAuto, &domain.ScanResult{Mode: "local"}, "warning: remote server unreachable, scanned against local database"},
		{"auto remote success", scanner.ModeAuto, &domain.ScanResult{Mode: "remote"}, ""},
		{"explicit local mode", scanner.ModeLocal, &domain.ScanResult{Mode: "local"}, ""},
		{"nil result", scanner.ModeAuto, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoFallbackWarning(tc.mode, tc.result); got != tc.want {
				t.Fatalf("autoFallbackWarning() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveScanPipelineInputValidatesSeverityAndMode(t *testing.T) {
	t.Parallel()

	input, err := resolveScanPipelineInput(scanSettings{FailOn: "NONE", Mode: " AUTO "})
	if err != nil {
		t.Fatalf("resolveScanPipelineInput(auto/NONE) error = %v", err)
	}
	if input.failOn != domain.SeverityNone || input.mode != scanner.ModeAuto {
		t.Fatalf("resolveScanPipelineInput(auto/NONE) = %+v", input)
	}

	input, err = resolveScanPipelineInput(scanSettings{FailOn: "CRITICAL", Mode: " Remote "})
	if err != nil {
		t.Fatalf("resolveScanPipelineInput(remote) error = %v", err)
	}
	if input.mode != scanner.ModeRemote {
		t.Fatalf("resolveScanPipelineInput(remote).mode = %q, want %q", input.mode, scanner.ModeRemote)
	}

	if _, err := resolveScanPipelineInput(scanSettings{FailOn: "BAD", Mode: "remote"}); err == nil || !strings.Contains(err.Error(), "invalid fail_on") {
		t.Fatalf("resolveScanPipelineInput(invalid fail_on) error = %v", err)
	}
	if _, err := resolveScanPipelineInput(scanSettings{FailOn: "CRITICAL", Mode: "sideways"}); err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("resolveScanPipelineInput(invalid mode) error = %v", err)
	}
}

func TestCLISeverityValidationUsesDomainParser(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"client_config.go", "scan.go"} {
		data, err := os.ReadFile(path) // #nosec G304 -- test inspects fixed package source files.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		if strings.Contains(text, "scanner.SeverityFromString") {
			t.Fatalf("%s still validates blocking severity through scanner table helper", path)
		}
		if !strings.Contains(text, "domain.ParseBlockThreshold(") {
			t.Fatalf("%s does not use the domain blocking severity parser", path)
		}
	}
}

func TestScanOutputArtifactRegistryDrivesOutputConditionals(t *testing.T) {
	t.Parallel()

	bannedSelectors := map[string]struct{}{
		"OutputJSON":  {},
		"OutputSARIF": {},
		"OutputJUnit": {},
		"OutputHTML":  {},
	}
	functions := map[string][]string{
		"scan.go": {
			"runScanCommand",
			"applyScanOutputFlagSettings",
			"applyOutputConfig",
			"writeScanOutputArtifacts",
		},
		"auto_sbom.go": {
			"hasAutoSBOMOnlyResultOutput",
			"validateAutoSBOMOnlySettings",
		},
	}

	for path, funcNames := range functions {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		decls := make(map[string]*ast.FuncDecl)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok {
				decls[fn.Name.Name] = fn
			}
		}

		for _, funcName := range funcNames {
			fn := decls[funcName]
			if fn == nil {
				t.Fatalf("%s missing function %s", path, funcName)
			}
			var hits []string
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if _, banned := bannedSelectors[selector.Sel.Name]; banned {
					pos := fset.Position(selector.Pos())
					hits = append(hits, fmt.Sprintf("%s:%d %s", path, pos.Line, selector.Sel.Name))
				}
				return true
			})
			if len(hits) > 0 {
				t.Fatalf("%s should use scanOutputArtifact registry instead of direct output fields:\n%s", funcName, strings.Join(hits, "\n"))
			}
		}
	}
}

func TestBuildScannerConfigMapsScanSettings(t *testing.T) {
	t.Parallel()

	repoInfo := &domain.RepoInfo{Name: "repo", Branch: "main", Commit: "abc"}
	cfg := buildScannerConfig(scanSettings{
		Path:             "src",
		ServerURL:        "https://packmon.example",
		APIKey:           "key",
		Ecosystems:       []string{"npm", "go"},
		MaxDepth:         7,
		Timeout:          9,
		IncludeDev:       true,
		InventoryAll:     true,
		Quiet:            true,
		NoColor:          true,
		CACertFile:       "ca.pem",
		InsecureHTTP:     true,
		RequireRemote:    true,
		OmitRepoMetadata: true,
		SBOMFiles:        []string{"bom.cdx.json"},
		LogLevel:         "debug",
		LogFormat:        "json",
	}, repoInfo, domain.SeverityHigh, scanner.ModeRemote)

	if cfg.Path != "src" || cfg.Mode != scanner.ModeRemote || cfg.ServerURL != "https://packmon.example" || cfg.APIKey != "key" {
		t.Fatalf("connection config = %+v", cfg)
	}
	if cfg.Repo != repoInfo || cfg.FailOn != domain.SeverityHigh || cfg.Timeout != 9*time.Second {
		t.Fatalf("scan policy config = %+v", cfg)
	}
	if !cfg.IncludeDev || !cfg.InventoryAllPackages || !cfg.Quiet || !cfg.NoColor || !cfg.AllowInsecureHTTP || !cfg.RequireRemote || !cfg.OmitRepoMetadata {
		t.Fatalf("bool config = %+v", cfg)
	}
	if got := strings.Join(cfg.Ecosystems, ","); got != "npm,go" {
		t.Fatalf("ecosystems = %q", got)
	}
	if got := strings.Join(cfg.SBOMFiles, ","); got != "bom.cdx.json" {
		t.Fatalf("SBOMFiles = %q", got)
	}
	if cfg.CACertFile != "ca.pem" || cfg.Version != version || cfg.Logger == nil {
		t.Fatalf("tls/version/logger config = %+v", cfg)
	}
}

func TestShouldRecordScanHistoryHonorsExitCodesAndEnv(t *testing.T) {
	t.Setenv("PACKMON_HISTORY_ENABLED", "true")

	for _, exitCode := range []int{ExitOK, ExitBlocking, ExitUnderThreshold} {
		got, err := shouldRecordScanHistory(exitCode)
		if err != nil {
			t.Fatalf("shouldRecordScanHistory(%d) error = %v", exitCode, err)
		}
		if !got {
			t.Fatalf("shouldRecordScanHistory(%d) = false, want true", exitCode)
		}
	}
	got, err := shouldRecordScanHistory(ExitOperational)
	if err != nil {
		t.Fatalf("shouldRecordScanHistory(ExitOperational) error = %v", err)
	}
	if got {
		t.Fatalf("shouldRecordScanHistory(ExitOperational) = true, want false")
	}

	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	got, err = shouldRecordScanHistory(ExitOK)
	if err != nil {
		t.Fatalf("shouldRecordScanHistory(ExitOK) disabled error = %v", err)
	}
	if got {
		t.Fatalf("shouldRecordScanHistory(ExitOK) with disabled history = true, want false")
	}
}

func TestRecordSuccessfulScanHistoryReturnsInsertFailureWithContext(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())
	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite store: %v", err)
	}

	result := &domain.ScanResult{
		PackagesScanned: 3,
		FindingsCount:   2,
	}
	repo := &domain.RepoInfo{Name: "app"}

	stderr := captureScanStderr(t, func() {
		err := recordSuccessfulScanHistory(context.Background(), store, repo, result, true, scanHistoryConfig{})
		if err == nil {
			t.Fatal("recordSuccessfulScanHistory() error = nil, want insert failure")
		}
		for _, want := range []string{"store scan history", "repo app", "packages=3", "findings=2"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("recordSuccessfulScanHistory() error = %q, want containing %q", err, want)
			}
		}
	})

	for _, want := range []string{"warning: unable to store scan history", "repo app", "packages=3", "findings=2"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want containing %q", stderr, want)
		}
	}
}

func TestReportScanParseErrorsCapsTerminalWarnings(t *testing.T) {
	result := &domain.ScanResult{ParseErrors: numberedParseDiagnostics(23)}

	stderr := captureScanStderr(t, func() {
		reportScanParseErrors(result)
	})

	if got := strings.Count(stderr, "warning: parse error in"); got != 20 {
		t.Fatalf("parse warning count = %d, want 20\n%s", got, stderr)
	}
	if !strings.Contains(stderr, "diagnostic-20") {
		t.Fatalf("stderr missing last visible diagnostic:\n%s", stderr)
	}
	for _, omitted := range []string{"diagnostic-21", "diagnostic-23"} {
		if strings.Contains(stderr, omitted) {
			t.Fatalf("stderr included omitted diagnostic %q:\n%s", omitted, stderr)
		}
	}
	if !strings.Contains(stderr, "3 additional parse diagnostics omitted; see JSON parse_errors for full detail") {
		t.Fatalf("stderr missing omitted-summary:\n%s", stderr)
	}
	if len(result.ParseErrors) != 23 || result.ParseErrors[22] != "diagnostic-23" {
		t.Fatalf("reportScanParseErrors mutated raw parse errors: %#v", result.ParseErrors)
	}
}

func numberedParseDiagnostics(count int) []string {
	out := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		out = append(out, fmt.Sprintf("diagnostic-%02d", i))
	}
	return out
}

func captureScanStderr(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = write
	defer func() { os.Stderr = original }()

	fn()

	if err := write.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	out, err := io.ReadAll(read)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if err := read.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	return string(out)
}

func TestScanHelpDocumentsOutdatedPublicRegistryEgress(t *testing.T) {
	t.Parallel()

	flag := newScanCmd().Flag("outdated")
	if flag == nil {
		t.Fatal("--outdated flag missing")
	}
	usage := strings.ToLower(flag.Usage)
	for _, want := range []string{"public registr", "git remote"} {
		if !strings.Contains(usage, want) {
			t.Fatalf("--outdated usage = %q, want privacy note containing %q", flag.Usage, want)
		}
	}
}

func TestBuildScanTargets_UsesLocalNameForRootPath(t *testing.T) {
	t.Parallel()

	targets, err := buildScanTargets(nil, []string{string(filepath.Separator)}, scanFlagValues{})
	if err != nil {
		t.Fatalf("build scan targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Name != "local" {
		t.Fatalf("target name = %q, want %q", targets[0].Name, "local")
	}
}

func TestWriteJSONFile_CreatesParentDirWithRestrictivePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	outputPath := filepath.Join(baseDir, "reports", "scan.json")

	if err := writeJSONFile(outputPath, &domain.ScanResult{}); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("stat output file: %v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	testutil.SkipIfPOSIXModesAreNotPreserved(t, baseDir)

	dirInfo, err := os.Stat(filepath.Dir(outputPath))
	if err != nil {
		t.Fatalf("stat output dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o750 {
		t.Fatalf("output dir perms = %o, want %o", dirInfo.Mode().Perm(), 0o750)
	}

	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("output file perms = %o, want %o", fileInfo.Mode().Perm(), 0o600)
	}
}

func TestWriteJSONFileTightensExistingFilePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	testutil.SkipIfPOSIXModesAreNotPreserved(t, baseDir)

	outputPath := filepath.Join(baseDir, "scan.json")
	if err := os.WriteFile(outputPath, []byte("old report"), 0o644); err != nil { // #nosec G306 -- test seeds broad permissions to verify the report writer tightens them.
		t.Fatalf("seed broad report file: %v", err)
	}
	if err := os.Chmod(outputPath, 0o644); err != nil { // #nosec G302 -- test intentionally prepares a too-broad existing file.
		t.Fatalf("chmod broad report file: %v", err)
	}

	if err := writeJSONFile(outputPath, &domain.ScanResult{}); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}

	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("output file perms = %o, want 0600", got)
	}
}

func TestStandaloneHTMLReportWritersTightenExistingFilePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	testutil.SkipIfPOSIXModesAreNotPreserved(t, baseDir)

	cases := []struct {
		name  string
		path  string
		write func(string) error
	}{
		{
			name: "list-all",
			path: filepath.Join(baseDir, "list-all.html"),
			write: func(path string) error {
				return writeListAllHTML(path, "svc", &domain.ScanResult{}, listAllPackageReport{})
			},
		},
		{
			name: "outdated",
			path: filepath.Join(baseDir, "outdated.html"),
			write: func(path string) error {
				return writeOutdatedHTML(path, outdatedReport{Total: 1, PackageWord: "package"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(tc.path, []byte("old report"), 0o644); err != nil { // #nosec G306 -- test seeds broad permissions to verify the report writer tightens them.
				t.Fatalf("seed broad report file: %v", err)
			}
			if err := os.Chmod(tc.path, 0o644); err != nil { // #nosec G302 -- test intentionally prepares a too-broad existing file.
				t.Fatalf("chmod broad report file: %v", err)
			}

			if err := tc.write(tc.path); err != nil {
				t.Fatalf("write report: %v", err)
			}

			fileInfo, err := os.Stat(tc.path)
			if err != nil {
				t.Fatalf("stat output file: %v", err)
			}
			if got := fileInfo.Mode().Perm(); got != 0o600 {
				t.Fatalf("output file perms = %o, want 0600", got)
			}
		})
	}
}
