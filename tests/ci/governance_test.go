package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
