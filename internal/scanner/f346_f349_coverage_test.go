package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/parser"
)

type f346FailWriter struct{}

func (f346FailWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced output failure")
}

func TestF346JUnitReachableOutputAndPolicyEdges(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{}
	if err := NewJUnitWriter().Write(f346FailWriter{}, result); err == nil || !strings.Contains(err.Error(), "forced output failure") {
		t.Fatalf("Write(output failure) = %v", err)
	}
	if err := NewJUnitWriter().WriteFile(t.TempDir(), result); err == nil || !strings.Contains(err.Error(), "junit: create file") {
		t.Fatalf("WriteFile(directory) = %v", err)
	}

	result = &domain.ScanResult{
		FindingsBlocking: true,
		BlockThreshold:   domain.SeverityCritical,
		Findings: []domain.Finding{{
			Name: "policy-blocked", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow,
		}},
	}
	suites := NewJUnitWriter().buildJUnit(result)
	if suites.Failures != 1 || len(suites.Testsuites) == 0 || suites.Testsuites[0].Cases[0].Failure == nil {
		t.Fatalf("policy-blocked JUnit suites = %#v, want one forced failure", suites)
	}
}

func TestF347CollectorReachableFailureAndFilterEdges(t *testing.T) {
	t.Parallel()

	empty, err := CollectPackages(CollectConfig{Root: t.TempDir()})
	if err != nil {
		t.Fatalf("CollectPackages(default registry): %v", err)
	}
	if len(empty.Packages) != 0 {
		t.Fatalf("CollectPackages(empty root) = %#v", empty.Packages)
	}

	missingRoot := filepath.Join(t.TempDir(), "missing")
	if err := collectLockfilePackages(&PackageCollection{}, parser.NewRegistry(), missingRoot, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "walk:") {
		t.Fatalf("collectLockfilePackages(missing root) = %v", err)
	}
	if _, err := parseCollectedLockFileUnderRoot(missingRoot, LockFile{}); err == nil {
		t.Fatal("parseCollectedLockFileUnderRoot(missing root) error = nil")
	}
	if _, err := parseCollectedLockFile(LockFile{Path: filepath.Join(missingRoot, "package-lock.json")}); err == nil {
		t.Fatal("parseCollectedLockFile(missing file) error = nil")
	}

	closedPath := filepath.Join(t.TempDir(), "closed.lock")
	if err := os.WriteFile(closedPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write closed-file fixture: %v", err)
	}
	closedFile, err := os.Open(closedPath) // #nosec G304 -- closedPath is a t.TempDir fixture.
	if err != nil {
		t.Fatalf("open closed-file fixture: %v", err)
	}
	if err := closedFile.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	if _, err := parseCollectedLockFileReader(closedFile, LockFile{Parser: parser.NewNPMParser()}); err == nil {
		t.Fatal("parseCollectedLockFileReader(closed file) error = nil")
	}

	root := t.TempDir()
	lockData := "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":{\"version\":\"1.0.0\"}}}"
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lockData), 0o600); err != nil {
		t.Fatalf("write lock fixture: %v", err)
	}
	lockResult := &PackageCollection{}
	if err := collectLockfilePackages(lockResult, parser.NewRegistry(), root, 1, nil, ecosystemFilter([]string{"pypi"})); err != nil {
		t.Fatalf("collect filtered lockfile: %v", err)
	}
	if lockResult.LockFiles != 1 || len(lockResult.Entries) != 0 {
		t.Fatalf("filtered lock result = %#v", lockResult)
	}

	sbomPath := filepath.Join(root, "bom.json")
	sbomData := "{\"bomFormat\":\"CycloneDX\",\"components\":[{\"type\":\"library\",\"name\":\"lodash\",\"purl\":\"pkg:npm/lodash@1.0.0\"}]}"
	if err := os.WriteFile(sbomPath, []byte(sbomData), 0o600); err != nil {
		t.Fatalf("write SBOM fixture: %v", err)
	}
	sbomResult := &PackageCollection{}
	if err := collectExplicitSBOMPackages(sbomResult, root, []string{" ", sbomPath}, ecosystemFilter([]string{"pypi"})); err != nil {
		t.Fatalf("collect filtered SBOM: %v", err)
	}
	if sbomResult.SBOMFiles != 1 || len(sbomResult.Entries) != 0 {
		t.Fatalf("filtered SBOM result = %#v", sbomResult)
	}

	missingSBOM := filepath.Join(root, "missing.json")
	if _, _, _, err := parseCollectedSBOM(root, missingSBOM); err == nil {
		t.Fatal("parseCollectedSBOM(missing file) error = nil")
	}
	err = collectExplicitSBOMPackages(&PackageCollection{}, root, []string{missingSBOM}, nil)
	var inputErr *sbomInputError
	if !errors.As(err, &inputErr) {
		t.Fatalf("collectExplicitSBOMPackages(missing file) = %v, want sbomInputError", err)
	}
}

func TestF347CollectorDiagnosticHelpers(t *testing.T) {
	t.Parallel()

	for reason, want := range map[string]string{
		"invalid package name":            "invalid package name",
		"missing purl":                    "missing purl",
		"unsupported component type":      "unsupported component type",
		"unsupported or versionless purl": "unsupported or versionless purl",
	} {
		if got := sbomSkippedComponentReason(reason); got != want {
			t.Errorf("sbomSkippedComponentReason(%q) = %q, want %q", reason, got, want)
		}
	}
	if got := safeExternalDisplayPath(string(filepath.Separator)); got != "external-sbom" {
		t.Fatalf("safeExternalDisplayPath(root) = %q", got)
	}
}

func TestF349ReportWarningsOmitsZeroPackageDiagnostic(t *testing.T) {
	t.Parallel()

	if got := ReportWarnings(&domain.ScanResult{}); got != nil {
		t.Fatalf("ReportWarnings(zero packages) = %q, want nil", got)
	}
	if got := scanOperationalStatusMessage(nil); got != "" {
		t.Fatalf("scanOperationalStatusMessage(nil) = %q", got)
	}
	if diagnostics := scanArtifactDiagnostics(&domain.ScanResult{}); len(diagnostics) != 1 || diagnostics[0].Message != zeroPackageScanWarning {
		t.Fatalf("zero-package diagnostics = %#v", diagnostics)
	}
}
