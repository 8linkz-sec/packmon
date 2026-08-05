package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newTestScanCmdForTLS builds a scan command with the TLS-related flags
// registered, mirroring newScanCmd's flag set, so flag-precedence can be
// exercised in isolation.
func newTestScanCmdForTLS() *cobra.Command {
	cmd := &cobra.Command{Use: "scan", RunE: func(*cobra.Command, []string) error { return nil }}
	f := cmd.Flags()
	f.String("mode", "auto", "")
	f.String("server", "", "")
	f.String("api-key", "", "")
	f.String("fail-on", "CRITICAL", "")
	f.String("ecosystems", "", "")
	f.Int("timeout", 30, "")
	f.Bool("include-dev", false, "")
	f.String("webhook-url", "", "")
	f.String("webhook-secret", "", "")
	f.String("cacert", "", "")
	f.Bool("insecure-allow-http", false, "")
	f.Bool("require-remote", false, "")
	f.Bool("no-repo-metadata", false, "")
	return cmd
}

func TestResolveScanSettings_TLSFlagsWin(t *testing.T) {
	t.Setenv("PACKMON_CA_CERT", "/env/ca.pem")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "false")
	t.Setenv("PACKMON_REQUIRE_REMOTE", "false")

	cmd := newTestScanCmdForTLS()
	if err := cmd.Flags().Set("cacert", "/flag/ca.pem"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("insecure-allow-http", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("require-remote", "true"); err != nil {
		t.Fatal(err)
	}

	flags := scanFlagValues{
		CACert:        "/flag/ca.pem",
		InsecureHTTP:  true,
		RequireRemote: true,
	}
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, nil, target, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.CACertFile != "/flag/ca.pem" {
		t.Fatalf("CACertFile = %q, want /flag/ca.pem (flag must win over env)", settings.CACertFile)
	}
	if !settings.InsecureHTTP {
		t.Fatal("InsecureHTTP should be true from flag")
	}
	if !settings.RequireRemote {
		t.Fatal("RequireRemote should be true from flag")
	}
}

func TestResolveScanSettings_TLSEnvApplied(t *testing.T) {
	t.Setenv("PACKMON_CA_CERT", "/env/ca.pem")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")
	t.Setenv("PACKMON_REQUIRE_REMOTE", "1")

	cmd := newTestScanCmdForTLS() // no flags changed
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, nil, target, scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.CACertFile != "/env/ca.pem" {
		t.Fatalf("CACertFile = %q, want /env/ca.pem from env", settings.CACertFile)
	}
	if !settings.InsecureHTTP {
		t.Fatal("InsecureHTTP should be true from env")
	}
	if !settings.RequireRemote {
		t.Fatal("RequireRemote should be true from env")
	}
}

func TestResolveScanSettingsCACertFileEnvWinsOverLegacyAlias(t *testing.T) {
	t.Setenv("PACKMON_CA_CERT", "/env/legacy-ca.pem")
	t.Setenv("PACKMON_CA_CERT_FILE", "/env/preferred-ca.pem")

	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, nil, target, scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.CACertFile != "/env/preferred-ca.pem" {
		t.Fatalf("CACertFile = %q, want preferred PACKMON_CA_CERT_FILE value", settings.CACertFile)
	}
}

func TestResolveScanSettingsRejectsInvalidBooleanEnv(t *testing.T) {
	t.Setenv("PACKMON_REQUIRE_REMOTE", "ture")

	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}
	_, err := resolveScanSettings(cmd, nil, target, scanFlagValues{})
	if err == nil || !strings.Contains(err.Error(), "PACKMON_REQUIRE_REMOTE") {
		t.Fatalf("resolveScanSettings() error = %v, want invalid PACKMON_REQUIRE_REMOTE rejection", err)
	}
}

func TestResolveScanSettingsRepoMetadataPrivacyPrecedence(t *testing.T) {
	t.Setenv("PACKMON_NO_REPO_METADATA", "true")

	sendRepoMetadata := true
	cfg := &cliConfig{SendRepoMetadata: &sendRepoMetadata}
	cmd := newTestScanCmdForTLS()
	if err := cmd.Flags().Set("no-repo-metadata", "false"); err != nil {
		t.Fatal(err)
	}
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, cfg, target, scanFlagValues{OmitRepoMetadata: false})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.OmitRepoMetadata {
		t.Fatal("OmitRepoMetadata should be false because explicit flag overrides env")
	}

	cmd = newTestScanCmdForTLS()
	settings, err = resolveScanSettings(cmd, cfg, target, scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings env: %v", err)
	}
	if !settings.OmitRepoMetadata {
		t.Fatal("OmitRepoMetadata should be true from PACKMON_NO_REPO_METADATA")
	}
}

func TestResolveScanSettingsRejectsInvalidRepoMetadataBooleanEnv(t *testing.T) {
	t.Setenv("PACKMON_NO_REPO_METADATA", "sometimes")

	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}
	_, err := resolveScanSettings(cmd, nil, target, scanFlagValues{})
	if err == nil || !strings.Contains(err.Error(), "PACKMON_NO_REPO_METADATA") {
		t.Fatalf("resolveScanSettings() error = %v, want invalid PACKMON_NO_REPO_METADATA rejection", err)
	}
}

func TestResolveScanSettingsRejectsInvalidTimeoutEnv(t *testing.T) {
	t.Setenv("PACKMON_TIMEOUT", "later")

	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}
	_, err := resolveScanSettings(cmd, nil, target, scanFlagValues{})
	if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT") {
		t.Fatalf("resolveScanSettings() error = %v, want invalid PACKMON_TIMEOUT rejection", err)
	}
}

func TestResolveScanSettings_TLSFromCLIConfig(t *testing.T) {
	// Ensure env does not interfere.
	t.Setenv("PACKMON_CA_CERT", "")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "")
	t.Setenv("PACKMON_REQUIRE_REMOTE", "")

	tru := true
	cfg := &cliConfig{
		CACert:            "/yaml/ca.pem",
		InsecureAllowHTTP: &tru,
		RequireRemote:     &tru,
	}
	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, cfg, target, scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.CACertFile != "/yaml/ca.pem" {
		t.Fatalf("CACertFile = %q, want /yaml/ca.pem from yaml", settings.CACertFile)
	}
	if !settings.InsecureHTTP {
		t.Fatal("InsecureHTTP should be true from yaml")
	}
	if !settings.RequireRemote {
		t.Fatal("RequireRemote should be true from yaml")
	}
}

func TestResolveScanSettings_APIKeyEnvFromCLIConfig(t *testing.T) {
	t.Setenv("PACKMON_API_KEY", "")
	t.Setenv("PACKMON_CI_KEY", "secret-from-env-ref")

	// #nosec G101 -- test fixture references an environment variable name, not a secret.
	cfg := &cliConfig{APIKeyEnv: "PACKMON_CI_KEY"}
	cmd := newTestScanCmdForTLS()
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, cfg, target, scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.APIKey != "secret-from-env-ref" {
		t.Fatalf("APIKey = %q, want value from api_key_env", settings.APIKey)
	}
}

func TestResolveScanSettings_APIKeyFlagOverridesMissingAPIKeyEnv(t *testing.T) {
	t.Setenv("PACKMON_API_KEY", "")
	t.Setenv("PACKMON_MISSING_KEY", "")
	t.Setenv("PACKMON_ALLOW_SECRET_FLAGS", "true")

	cfg := &cliConfig{APIKeyEnv: "PACKMON_MISSING_KEY"}
	cmd := newTestScanCmdForTLS()
	if err := cmd.Flags().Set("api-key", "secret-from-flag"); err != nil {
		t.Fatal(err)
	}
	target := scanTarget{Name: "local", Path: "."}

	settings, err := resolveScanSettings(cmd, cfg, target, scanFlagValues{APIKey: "secret-from-flag"})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if settings.APIKey != "secret-from-flag" {
		t.Fatalf("APIKey = %q, want flag value", settings.APIKey)
	}
}
