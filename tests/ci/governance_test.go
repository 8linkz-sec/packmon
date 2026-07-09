package ci

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestGitHubCIWorkflowRunsSecretScanning(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	security, ok := wf.Jobs["security"]
	if !ok {
		t.Fatal("ci workflow has no security job")
	}
	runs := joinedStepRuns(security.Steps)
	for _, want := range []string{
		"go install github.com/gitleaks/gitleaks/v8@",
		"gitleaks detect",
		"--source .",
		"--redact",
		"--no-banner",
	} {
		if !strings.Contains(runs, want) {
			t.Fatalf("security job missing secret-scanning marker %q", want)
		}
	}
	if strings.Contains(runs, "gitleaks/gitleaks/v8@latest") {
		t.Fatal("secret scanner must be pinned to an explicit version, not latest")
	}
}

func TestGitHubSemgrepWorkflowRunsStaticSecurityAnalysis(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "semgrep.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read semgrep.yml: %v", err)
	}

	var wf struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse semgrep.yml: %v", err)
	}
	if wf.Permissions["contents"] != "read" {
		t.Fatalf("semgrep workflow contents permission = %q, want read", wf.Permissions["contents"])
	}

	semgrep, ok := wf.Jobs["semgrep"]
	if !ok {
		t.Fatal("semgrep workflow has no semgrep job")
	}
	runs := joinedStepRuns(semgrep.Steps)
	for _, want := range []string{
		"python -m pip install semgrep==",
		"semgrep scan",
		"--config p/default",
		"--severity ERROR",
		"--error",
		"--sarif",
		"--output semgrep.sarif",
		"--metrics=off",
		"--disable-version-check",
	} {
		if !strings.Contains(runs, want) {
			t.Fatalf("semgrep workflow missing static analysis marker %q", want)
		}
	}
	if strings.Contains(runs, "semgrep==latest") || strings.Contains(runs, "semgrep scan --config auto") {
		t.Fatal("semgrep workflow must pin Semgrep and avoid opaque auto configuration")
	}
}

func TestPullRequestTemplateIncludesSecurityChecklist(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "PULL_REQUEST_TEMPLATE.md")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read pull request template: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"## Security Checklist",
		"auth, CSRF, API keys, admin sessions, or webhook/feed-import secrets",
		"logs, metrics, errors, or artifacts do not expose secrets",
		"migrations, feed integrity, CI/CD, release, or deployment behavior",
		"`SECURITY.md` updated or not needed",
		"`DESIGN.md` updated or not needed",
		"relevant security/CI validation commands",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("pull request template missing security checklist marker %q", want)
		}
	}
}

func TestReleaseWorkflowUsesProtectedEnvironmentGate(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Environment any `yaml:"environment"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	release, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release workflow has no release job")
	}
	if got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(toString(release.Environment), "]"), "[")); got != "release" {
		t.Fatalf("release job environment = %#v, want release", release.Environment)
	}
}

func TestCodeownersRoutesSensitiveAreas(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "CODEOWNERS")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read CODEOWNERS: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		".github/workflows/",
		"ci/",
		"deploy/",
		"Dockerfile",
		"docker-compose.yml",
		"SECURITY.md",
		"DESIGN.md",
		"cmd/packmon-server/",
		"internal/server/",
		"internal/api/",
		"internal/db/",
		"internal/feed/",
		"internal/auth/",
		"api/openapi/",
	} {
		if !codeownersContainsPath(text, want) {
			t.Fatalf("CODEOWNERS missing sensitive path %q", want)
		}
	}
	if !strings.Contains(text, "@8linkz-sec/") {
		t.Fatal("CODEOWNERS must route sensitive paths to an 8linkz-sec owner")
	}
}

func TestAdminAccessCompensatingControlIsDocumented(t *testing.T) {
	t.Parallel()

	securityPath := filepath.Join("..", "..", "SECURITY.md")
	securityData, err := os.ReadFile(securityPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	security := string(securityData)
	for _, want := range []string{
		"Privileged Admin Access Compensating Control",
		"Packmon does not implement built-in MFA",
		"reverse proxy or identity provider",
		"multi-factor authentication",
		"SSO",
		"one shared admin identity",
	} {
		if !strings.Contains(security, want) {
			t.Fatalf("SECURITY.md missing admin access control marker %q", want)
		}
	}

	runbookPath := filepath.Join("..", "..", "docs", "runbook.md")
	runbookData, err := os.ReadFile(runbookPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	runbook := string(runbookData)
	for _, want := range []string{
		"Admin Access Control",
		"enforce MFA or SSO",
		"trusted reverse proxy",
		"restrict /admin",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("docs/runbook.md missing admin access control marker %q", want)
		}
	}
}

func TestSecureCodingGuidanceIsDocumented(t *testing.T) {
	t.Parallel()

	guidePath := filepath.Join("..", "..", "docs", "secure-coding.md")
	guideData, err := os.ReadFile(guidePath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read secure coding guide: %v", err)
	}
	guide := string(guideData)
	for _, want := range []string{
		"Secure Coding and Security Awareness",
		"security-sensitive changes",
		"threat model",
		"authentication, authorization, CSRF, sessions, or API keys",
		"secrets, file contents, full paths, or environment values",
		"dependency and feed-provider changes",
		"security validation commands",
		"review this guide during onboarding",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("docs/secure-coding.md missing marker %q", want)
		}
	}

	for _, path := range []string{
		filepath.Join("..", "..", "CONTRIBUTING.md"),
		filepath.Join("..", "..", "SECURITY.md"),
		filepath.Join("..", "..", "README.md"),
	} {
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), "docs/secure-coding.md") {
			t.Fatalf("%s missing secure coding guide link", path)
		}
	}
}

func TestRiskRegisterIsDocumented(t *testing.T) {
	t.Parallel()

	registerPath := filepath.Join("..", "..", "docs", "risk-register.md")
	registerData, err := os.ReadFile(registerPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read risk register: %v", err)
	}
	register := string(registerData)
	for _, want := range []string{
		"Risk Assessment and Treatment Register",
		"Review cadence",
		"Risk ID",
		"Owner",
		"Treatment",
		"Residual risk",
		"shared admin identity",
		"feed-provider compromise",
		"public exposure of internal services",
		"secret or log disclosure",
	} {
		if !strings.Contains(register, want) {
			t.Fatalf("docs/risk-register.md missing marker %q", want)
		}
	}
	for _, path := range []string{
		filepath.Join("..", "..", "SECURITY.md"),
		filepath.Join("..", "..", "README.md"),
	} {
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), "docs/risk-register.md") {
			t.Fatalf("%s missing risk register link", path)
		}
	}
}

func TestSupplierSecurityAssessmentIsDocumented(t *testing.T) {
	t.Parallel()

	assessmentPath := filepath.Join("..", "..", "docs", "supplier-security.md")
	assessmentData, err := os.ReadFile(assessmentPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read supplier assessment: %v", err)
	}
	assessment := string(assessmentData)
	for _, want := range []string{
		"Supplier Security Assessment",
		"Provider",
		"Data exchanged",
		"Security dependency",
		"Review cadence",
		"OSV",
		"GHSA",
		"OpenSSF",
		"CISA KEV",
		"EPSS",
		"NVD",
		"endoflife.date",
		"VulnCheck",
		"Socket.dev",
		"ReversingLabs",
		"CycloneDX tooling",
	} {
		if !strings.Contains(assessment, want) {
			t.Fatalf("docs/supplier-security.md missing marker %q", want)
		}
	}
	for _, path := range []string{
		filepath.Join("..", "..", "SECURITY.md"),
		filepath.Join("..", "..", "README.md"),
	} {
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), "docs/supplier-security.md") {
			t.Fatalf("%s missing supplier assessment link", path)
		}
	}
}

func codeownersContainsPath(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == want {
			return true
		}
	}
	return false
}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		if name, ok := typed["name"].(string); ok {
			return name
		}
	}
	return fmt.Sprint(value)
}
