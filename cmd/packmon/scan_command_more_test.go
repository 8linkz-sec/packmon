package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/spf13/cobra"
)

func TestScanFailOnFlagHelpExplainsNoneScope(t *testing.T) {
	cmd := newScanCmd()
	flag := cmd.Flags().Lookup("fail-on")
	if flag == nil {
		t.Fatal("scan command missing --fail-on flag")
	}
	for _, want := range []string{
		"NONE disables vulnerability blocking only",
		"malicious and active supply-chain risk findings still block",
	} {
		if !strings.Contains(flag.Usage, want) {
			t.Fatalf("--fail-on usage missing %q:\n%s", want, flag.Usage)
		}
	}
}

func TestResolveScanSettingsPrecedenceAndValidation(t *testing.T) {
	t.Setenv("PACKMON_SERVER", "https://env.example")
	t.Setenv("PACKMON_API_KEY", "env-key")
	t.Setenv("PACKMON_MODE", "local")
	t.Setenv("PACKMON_FAIL_ON", "MEDIUM")
	t.Setenv("PACKMON_TIMEOUT", "44")
	t.Setenv("PACKMON_ECOSYSTEMS", "go,npm")
	t.Setenv("PACKMON_WEBHOOK_URL", "https://env.example/hook")
	t.Setenv("PACKMON_WEBHOOK_SECRET", "env-secret")
	t.Setenv("PACKMON_CA_CERT", "env-ca.pem")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")
	t.Setenv("PACKMON_REQUIRE_REMOTE", "true")
	t.Setenv("PACKMON_ALLOW_SECRET_FLAGS", "true")

	includeDev := true
	repoIncludeDev := false
	cfg := &cliConfig{
		Server:            "https://config.example",
		APIKey:            "config-key",
		Mode:              "remote",
		FailOn:            "HIGH",
		Timeout:           31,
		Ecosystems:        []string{"pypi"},
		IncludeDev:        &includeDev,
		CACert:            "config-ca.pem",
		InsecureAllowHTTP: &includeDev,
		RequireRemote:     &includeDev,
		Webhook: cliWebhookConfig{
			URL:    "https://config.example/hook",
			Secret: "config-secret",
		},
	}
	repo := &cliRepoConfig{
		Server:     "https://repo.example",
		APIKey:     "repo-key",
		Mode:       "auto",
		FailOn:     "LOW",
		Timeout:    32,
		Ecosystems: []string{"cargo"},
		IncludeDev: &repoIncludeDev,
		Webhook: cliWebhookConfig{
			URL:    "https://repo.example/hook",
			Secret: "repo-secret",
		},
	}

	cmd := newScanCmd()
	mustSetFlag(t, cmd, "mode", "remote")
	mustSetFlag(t, cmd, "server", "https://flag.example")
	mustSetFlag(t, cmd, "api-key", "flag-key")
	mustSetFlag(t, cmd, "fail-on", "CRITICAL")
	mustSetFlag(t, cmd, "ecosystems", "gem,composer")
	mustSetFlag(t, cmd, "timeout", "55")
	mustSetFlag(t, cmd, "include-dev", "true")
	mustSetFlag(t, cmd, "webhook-url", "https://flag.example/hook")
	mustSetFlag(t, cmd, "webhook-secret", "flag-secret")
	mustSetFlag(t, cmd, "cacert", "flag-ca.pem")
	mustSetFlag(t, cmd, "insecure-allow-http", "false")
	mustSetFlag(t, cmd, "require-remote", "false")
	mustSetFlag(t, cmd, "html", "result.html")
	mustSetFlag(t, cmd, "sbom", "bom-one.cdx.json")
	mustSetFlag(t, cmd, "sbom", "bom-two.spdx.json")

	settings, err := resolveScanSettings(cmd, cfg, scanTarget{Name: "repo", Path: ".", Repo: repo}, scanFlagValues{
		Mode:          "remote",
		Server:        "https://flag.example",
		APIKey:        "flag-key",
		FailOn:        "CRITICAL",
		Ecosystems:    "gem,composer",
		MaxDepth:      9,
		Timeout:       55,
		IncludeDev:    true,
		OutputJSON:    "result.json",
		OutputSARIF:   "result.sarif",
		OutputJUnit:   "result.xml",
		OutputHTML:    "result.html",
		WebhookURL:    "https://flag.example/hook",
		WebhookSecret: "flag-secret",
		CACert:        "flag-ca.pem",
		InsecureHTTP:  false,
		RequireRemote: false,
		SBOMFiles:     []string{"bom-one.cdx.json", "bom-two.spdx.json"},
		Quiet:         true,
		NoColor:       true,
	})
	if err != nil {
		t.Fatalf("resolve scan settings: %v", err)
	}

	if settings.ServerURL != "https://flag.example" || settings.APIKey != "flag-key" || settings.Mode != "remote" {
		t.Fatalf("flag precedence not applied: %+v", settings)
	}
	if settings.FailOn != "CRITICAL" || settings.Timeout != 55 || !settings.IncludeDev {
		t.Fatalf("flag scalar settings not applied: %+v", settings)
	}
	if got := strings.Join(settings.Ecosystems, ","); got != "gem,composer" {
		t.Fatalf("ecosystems = %q", got)
	}
	if settings.WebhookURL != "https://flag.example/hook" || settings.WebhookSecret != "flag-secret" || settings.CACertFile != "flag-ca.pem" {
		t.Fatalf("flag webhook/tls settings not applied: %+v", settings)
	}
	if settings.InsecureHTTP || settings.RequireRemote {
		t.Fatalf("flag bool overrides not applied: insecure=%v requireRemote=%v", settings.InsecureHTTP, settings.RequireRemote)
	}
	if settings.OutputJSON != "result.json" || settings.OutputSARIF != "result.sarif" ||
		settings.OutputJUnit != "result.xml" || settings.OutputHTML != "result.html" {
		t.Fatalf("output paths not applied: %+v", settings)
	}
	if got := strings.Join(settings.SBOMFiles, ","); got != "bom-one.cdx.json,bom-two.spdx.json" {
		t.Fatalf("SBOMFiles = %q", got)
	}
}

func TestApplyScanSharedSettingsMatchesConfigAndRepoCommonFields(t *testing.T) {
	t.Setenv("PACKMON_SHARED_SCAN_API_KEY", "shared-env-key")

	includeDev := true
	sendRepoMetadata := false
	//nolint:gosec // G101: fixture credential, deliberately fake.
	shared := scanSharedSettings{
		ServerURL:        "https://shared.example",
		APIKeyEnv:        "PACKMON_SHARED_SCAN_API_KEY",
		Mode:             "remote",
		FailOn:           "LOW",
		Timeout:          17,
		Ecosystems:       []string{"npm"},
		IncludeDev:       &includeDev,
		SendRepoMetadata: &sendRepoMetadata,
		WebhookURL:       "https://shared.example/hook",
		WebhookSecret:    "shared-secret",
	}

	want := defaultScanSettings(scanTarget{Name: "helper", Path: "."}, scanFlagValues{})
	if err := applyScanSharedSettings(&want, shared, false); err != nil {
		t.Fatalf("applyScanSharedSettings() error = %v", err)
	}

	configSettings := defaultScanSettings(scanTarget{Name: "config", Path: "."}, scanFlagValues{})
	if err := applyScanConfigSettings(&configSettings, &cliConfig{
		Server:           shared.ServerURL,
		APIKeyEnv:        shared.APIKeyEnv,
		Mode:             shared.Mode,
		FailOn:           shared.FailOn,
		Timeout:          shared.Timeout,
		Ecosystems:       append([]string(nil), shared.Ecosystems...),
		IncludeDev:       shared.IncludeDev,
		SendRepoMetadata: shared.SendRepoMetadata,
		Webhook:          cliWebhookConfig{URL: shared.WebhookURL, Secret: shared.WebhookSecret},
	}, false); err != nil {
		t.Fatalf("applyScanConfigSettings() error = %v", err)
	}
	assertScanCommonSettingsEqual(t, "config", configSettings, want)

	repoSettings := defaultScanSettings(scanTarget{Name: "repo", Path: "."}, scanFlagValues{})
	if err := applyScanRepoSettings(&repoSettings, &cliRepoConfig{
		Server:           shared.ServerURL,
		APIKeyEnv:        shared.APIKeyEnv,
		Mode:             shared.Mode,
		FailOn:           shared.FailOn,
		Timeout:          shared.Timeout,
		Ecosystems:       append([]string(nil), shared.Ecosystems...),
		IncludeDev:       shared.IncludeDev,
		SendRepoMetadata: shared.SendRepoMetadata,
		Webhook:          cliWebhookConfig{URL: shared.WebhookURL, Secret: shared.WebhookSecret},
	}, false); err != nil {
		t.Fatalf("applyScanRepoSettings() error = %v", err)
	}
	assertScanCommonSettingsEqual(t, "repo", repoSettings, want)
}

func assertScanCommonSettingsEqual(t *testing.T, label string, got, want scanSettings) {
	t.Helper()

	if got.ServerURL != want.ServerURL || got.APIKey != want.APIKey ||
		got.Mode != want.Mode || got.FailOn != want.FailOn ||
		got.Timeout != want.Timeout || got.IncludeDev != want.IncludeDev ||
		got.OmitRepoMetadata != want.OmitRepoMetadata ||
		got.WebhookURL != want.WebhookURL || got.WebhookSecret != want.WebhookSecret {
		t.Fatalf("%s shared settings = %+v, want common fields from %+v", label, got, want)
	}
	if strings.Join(got.Ecosystems, ",") != strings.Join(want.Ecosystems, ",") {
		t.Fatalf("%s ecosystems = %q, want %q", label, strings.Join(got.Ecosystems, ","), strings.Join(want.Ecosystems, ","))
	}
}

func TestResolveScanSettingsRejectsSecretFlagsByDefault(t *testing.T) {
	tests := []struct {
		name       string
		flagName   string
		flagValue  string
		flags      scanFlagValues
		leaked     string
		wantPieces []string
	}{
		{
			name:      "api key",
			flagName:  "api-key",
			flagValue: "argv-api-secret",
			//nolint:gosec // G101: fixture credential, deliberately fake.
			flags: scanFlagValues{
				APIKey: "argv-api-secret",
			},
			leaked: "argv-api-secret",
			wantPieces: []string{
				"--api-key",
				"PACKMON_API_KEY",
				"PACKMON_ALLOW_SECRET_FLAGS",
			},
		},
		{
			name:      "webhook secret",
			flagName:  "webhook-secret",
			flagValue: "argv-webhook-secret",
			//nolint:gosec // G101: fixture credential, deliberately fake.
			flags: scanFlagValues{
				WebhookSecret: "argv-webhook-secret",
			},
			leaked: "argv-webhook-secret",
			wantPieces: []string{
				"--webhook-secret",
				"PACKMON_WEBHOOK_SECRET",
				"PACKMON_ALLOW_SECRET_FLAGS",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd()
			mustSetFlag(t, cmd, tt.flagName, tt.flagValue)

			_, err := resolveScanSettings(cmd, nil, scanTarget{Name: "repo", Path: "."}, tt.flags)
			if err == nil {
				t.Fatalf("resolveScanSettings() error = nil, want %s rejection", tt.flagName)
			}
			for _, want := range tt.wantPieces {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("resolveScanSettings() error = %v, want %q", err, want)
				}
			}
			if strings.Contains(err.Error(), tt.leaked) {
				t.Fatalf("resolveScanSettings() error leaked secret %q: %v", tt.leaked, err)
			}
		})
	}
}

func TestResolveScanSettingsAppliesLatestRegistryMirrors(t *testing.T) {
	t.Setenv("PACKMON_NPM_REGISTRY_BASE_URL", "https://npm-env.example/registry")
	t.Setenv("PACKMON_PYPI_API_BASE_URL", "https://pypi-env.example/pypi")
	t.Setenv("PACKMON_RUBYGEMS_API_BASE_URL", "https://rubygems-env.example/api/v1/gems")
	t.Setenv("PACKMON_CARGO_REGISTRY_API_BASE_URL", "https://cargo-env.example/api/v1/crates")
	t.Setenv("PACKMON_COCOAPODS_TRUNK_API_BASE_URL", "https://cocoapods-env.example/api/v1/pods")
	t.Setenv("PACKMON_COMPOSER_REPOSITORY_BASE_URL", "https://composer-env.example/p2")
	t.Setenv("PACKMON_GO_PROXY_URL", "https://go-env.example")
	t.Setenv("PACKMON_MAVEN_REPOSITORY_BASE_URL", "https://maven-env.example/repository/maven-public")
	t.Setenv("PACKMON_DOCKER_REGISTRY_MIRRORS", "docker.io=https://docker-env.example/dockerhub,ghcr.io=https://ghcr-env.example")
	t.Setenv("PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS", "git-env.example,gitlab-env.example")
	t.Setenv("PACKMON_CRAN_MIRROR_URL", "https://cran-env.example")
	t.Setenv("PACKMON_PUB_HOSTED_URL", "https://pub-env.example")
	t.Setenv("PACKMON_HEX_API_BASE_URL", "https://hex-env.example/api")
	t.Setenv("PACKMON_NUGET_V3_BASE_URL", "https://nuget-env.example/v3-flatcontainer")

	cfg := &cliConfig{
		Registries: cliRegistryConfig{
			NPMRegistryBaseURL:        "https://npm-config.example/registry",
			PyPIAPIBaseURL:            "https://pypi-config.example/pypi",
			RubyGemsAPIBaseURL:        "https://rubygems-config.example/api/v1/gems",
			CargoRegistryAPIBaseURL:   "https://cargo-config.example/api/v1/crates",
			CocoaPodsTrunkAPIBaseURL:  "https://cocoapods-config.example/api/v1/pods",
			ComposerRepositoryBaseURL: "https://composer-config.example/p2",
			GoModuleProxyURL:          "https://go-config.example",
			MavenRepositoryBaseURL:    "https://maven-config.example/repository/maven-public",
			DockerRegistryMirrors:     map[string]string{"docker.io": "https://docker-config.example/dockerhub"},
			SwiftPMGitAllowedHosts:    []string{"git-config.example"},
			CRANMirrorURL:             "https://cran-config.example",
			PubHostedURL:              "https://pub-config.example",
			HexAPIBaseURL:             "https://hex-config.example/api",
			NuGetV3BaseURL:            "https://nuget-config.example/v3-flatcontainer",
		},
	}

	settings, err := resolveScanSettings(newScanCmd(), cfg, scanTarget{Name: "repo", Path: "."}, scanFlagValues{
		Mode:    "local",
		FailOn:  "CRITICAL",
		Timeout: 1,
	})
	if err != nil {
		t.Fatalf("resolve scan settings: %v", err)
	}
	if got := settings.LatestRegistry.NPMRegistryBaseURL; got != "https://npm-env.example/registry" {
		t.Fatalf("NPMRegistryBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.PyPIAPIBaseURL; got != "https://pypi-env.example/pypi" {
		t.Fatalf("PyPIAPIBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.RubyGemsAPIBaseURL; got != "https://rubygems-env.example/api/v1/gems" {
		t.Fatalf("RubyGemsAPIBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.CargoRegistryAPIBaseURL; got != "https://cargo-env.example/api/v1/crates" {
		t.Fatalf("CargoRegistryAPIBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.CocoaPodsTrunkAPIBaseURL; got != "https://cocoapods-env.example/api/v1/pods" {
		t.Fatalf("CocoaPodsTrunkAPIBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.ComposerRepositoryBaseURL; got != "https://composer-env.example/p2" {
		t.Fatalf("ComposerRepositoryBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.GoModuleProxyURL; got != "https://go-env.example" {
		t.Fatalf("GoModuleProxyURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.MavenRepositoryBaseURL; got != "https://maven-env.example/repository/maven-public" {
		t.Fatalf("MavenRepositoryBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.DockerRegistryMirrors["registry-1.docker.io"]; got != "https://docker-env.example/dockerhub" {
		t.Fatalf("DockerRegistryMirrors[docker] = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.DockerRegistryMirrors["ghcr.io"]; got != "https://ghcr-env.example" {
		t.Fatalf("DockerRegistryMirrors[ghcr] = %q, want env mirror", got)
	}
	if got := strings.Join(settings.LatestRegistry.SwiftPMGitAllowedHosts, ","); got != "git-env.example,gitlab-env.example" {
		t.Fatalf("SwiftPMGitAllowedHosts = %q, want env hosts", got)
	}
	if got := settings.LatestRegistry.CRANMirrorURL; got != "https://cran-env.example" {
		t.Fatalf("CRANMirrorURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.PubHostedURL; got != "https://pub-env.example" {
		t.Fatalf("PubHostedURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.HexAPIBaseURL; got != "https://hex-env.example/api" {
		t.Fatalf("HexAPIBaseURL = %q, want env mirror", got)
	}
	if got := settings.LatestRegistry.NuGetV3BaseURL; got != "https://nuget-env.example/v3-flatcontainer" {
		t.Fatalf("NuGetV3BaseURL = %q, want env mirror", got)
	}
	if !settings.LatestRegistry.NPMRegistryBaseURLConfigured ||
		!settings.LatestRegistry.PyPIAPIBaseURLConfigured ||
		!settings.LatestRegistry.RubyGemsAPIBaseURLConfigured ||
		!settings.LatestRegistry.CargoRegistryAPIBaseURLConfigured ||
		!settings.LatestRegistry.CocoaPodsTrunkAPIBaseURLConfigured ||
		!settings.LatestRegistry.ComposerRepositoryBaseURLConfigured ||
		!settings.LatestRegistry.GoModuleProxyURLConfigured ||
		!settings.LatestRegistry.MavenRepositoryBaseURLConfigured ||
		!settings.LatestRegistry.CRANMirrorURLConfigured ||
		!settings.LatestRegistry.SwiftPMGitAllowedHostsConfigured ||
		!settings.LatestRegistry.PubHostedURLConfigured ||
		!settings.LatestRegistry.HexAPIBaseURLConfigured ||
		!settings.LatestRegistry.NuGetV3BaseURLConfigured {
		t.Fatalf("LatestRegistry configured flags = %+v, want all mirrors true", settings.LatestRegistry)
	}
}

func TestResolveScanSettingsRejectsUnsafeLatestRegistryMirrorEnv(t *testing.T) {
	t.Setenv("PACKMON_HEX_API_BASE_URL", "http://hex-mirror.example/api")

	_, err := resolveScanSettings(newScanCmd(), nil, scanTarget{Name: "repo", Path: "."}, scanFlagValues{
		Mode:    "local",
		FailOn:  "CRITICAL",
		Timeout: 1,
	})
	if err == nil {
		t.Fatal("resolveScanSettings() error = nil, want unsafe mirror rejection")
	}
	if !strings.Contains(err.Error(), "PACKMON_HEX_API_BASE_URL") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("resolveScanSettings() error = %v, want explicit HTTPS mirror error", err)
	}
}

func TestResolveScanSettingsRejectsUnknownEcosystemFilters(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *cliConfig
		env     string
		flag    string
		listAll bool
	}{
		{
			name: "flag",
			flag: "npm,nmp",
		},
		{
			name: "environment",
			env:  "nmp",
		},
		{
			name: "config",
			cfg:  &cliConfig{Ecosystems: []string{"nmp"}},
		},
		{
			name: "repo config",
			cfg: &cliConfig{
				Repos: []cliRepoConfig{{
					Name:       "app",
					Path:       ".",
					Ecosystems: []string{"nmp"},
				}},
			},
		},
		{
			name:    "list all",
			flag:    "docker,nmp",
			listAll: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd()
			if tt.flag != "" {
				mustSetFlag(t, cmd, "ecosystems", tt.flag)
			}
			if tt.env != "" {
				t.Setenv("PACKMON_ECOSYSTEMS", tt.env)
			}
			target := scanTarget{Name: "app", Path: "."}
			if tt.name == "repo config" {
				target.Repo = &tt.cfg.Repos[0]
			}
			_, err := resolveScanSettings(cmd, tt.cfg, target, scanFlagValues{
				Mode:       "local",
				FailOn:     "CRITICAL",
				Ecosystems: tt.flag,
				Timeout:    1,
				ListAll:    tt.listAll,
			})
			if err == nil {
				t.Fatal("resolveScanSettings() error = nil, want unknown ecosystem rejection")
			}
			if !strings.Contains(err.Error(), `unknown ecosystem filter "nmp"`) {
				t.Fatalf("resolveScanSettings() error = %v, want unknown ecosystem", err)
			}
			if !strings.Contains(err.Error(), "valid values") {
				t.Fatalf("resolveScanSettings() error = %v, want valid values list", err)
			}
		})
	}
}

func TestResolveScanSettingsAllowsDockerOnlyForListAll(t *testing.T) {
	cmd := newScanCmd()
	mustSetFlag(t, cmd, "ecosystems", "docker,npm")

	settings, err := resolveScanSettings(cmd, nil, scanTarget{Path: "."}, scanFlagValues{
		Mode:       "local",
		FailOn:     "CRITICAL",
		Ecosystems: "docker,npm",
		Timeout:    1,
		ListAll:    true,
	})
	if err != nil {
		t.Fatalf("resolveScanSettings(list-all docker) error = %v", err)
	}
	if got := strings.Join(settings.Ecosystems, ","); got != "docker,npm" {
		t.Fatalf("ecosystems = %q, want docker,npm", got)
	}

	_, err = resolveScanSettings(cmd, nil, scanTarget{Path: "."}, scanFlagValues{
		Mode:       "local",
		FailOn:     "CRITICAL",
		Ecosystems: "docker,npm",
		Timeout:    1,
	})
	if err == nil || !strings.Contains(err.Error(), `unknown ecosystem filter "docker"`) {
		t.Fatalf("resolveScanSettings(scan docker) error = %v, want docker rejection", err)
	}
}

func TestResolveScanSettingsAllowsChocolateyOnlyForListAll(t *testing.T) {
	cmd := newScanCmd()
	mustSetFlag(t, cmd, "ecosystems", "chocolatey")

	settings, err := resolveScanSettings(cmd, nil, scanTarget{Path: "."}, scanFlagValues{
		Mode:       "local",
		FailOn:     "CRITICAL",
		Ecosystems: "chocolatey",
		Timeout:    1,
		ListAll:    true,
	})
	if err != nil {
		t.Fatalf("resolveScanSettings(list-all chocolatey) error = %v", err)
	}
	if got := strings.Join(settings.Ecosystems, ","); got != "chocolatey" {
		t.Fatalf("ecosystems = %q, want chocolatey", got)
	}

	_, err = resolveScanSettings(cmd, nil, scanTarget{Path: "."}, scanFlagValues{
		Mode:       "local",
		FailOn:     "CRITICAL",
		Ecosystems: "chocolatey",
		Timeout:    1,
	})
	if err == nil || !strings.Contains(err.Error(), `unknown ecosystem filter "chocolatey"`) {
		t.Fatalf("resolveScanSettings(scan chocolatey) error = %v, want chocolatey rejection", err)
	}
}

func TestRunScanCommandRejectsOutputFilesForMultipleTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	if err := os.WriteFile(".packmon.yaml", []byte(`
repos:
  - name: app
    path: "."
  - name: api
    path: "."
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newScanCmd()
	err := runScanCommand(cmd, nil, scanFlagValues{All: true, OutputJSON: "result.json"})
	if err == nil {
		t.Fatal("runScanCommand multiple targets with output file error = nil")
	}
	if !strings.Contains(err.Error(), "can only be used when scanning a single target") {
		t.Fatalf("runScanCommand error = %v", err)
	}
}

func TestOpenLocalSQLiteStoreReportsAdvisoryAvailability(t *testing.T) {
	dbDir := t.TempDir()
	store, dbPath := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close empty store: %v", err)
	}

	emptyStore, advisoryDataAvailable, err := openLocalSQLiteStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open empty local store: %v", err)
	}
	if advisoryDataAvailable {
		t.Fatal("advisoryDataAvailable(empty) = true")
	}
	if err := emptyStore.Close(); err != nil {
		t.Fatalf("close empty opened store: %v", err)
	}

	seedStore, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	_, err = seedStore.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity)
		VALUES('GHSA-open|npm|pkg', 'GHSA-open', 'npm', 'pkg', 'LOW')`)
	if err != nil {
		t.Fatalf("seed advisory data: %v", err)
	}
	if err := seedStore.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}

	seededStore, advisoryDataAvailable, err := openLocalSQLiteStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open seeded local store: %v", err)
	}
	defer ioutils.CloseSilently(seededStore)
	if !advisoryDataAvailable {
		t.Fatal("advisoryDataAvailable(seeded) = false")
	}
}

func TestRunListPackagesPrintsDetectedPackages(t *testing.T) {
	projectDir := t.TempDir()
	lockContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.15"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runListPackagesWithSettings(scanSettings{
			Path:       projectDir,
			Ecosystems: []string{"npm"},
			MaxDepth:   10,
			IncludeDev: true,
		}); err != nil {
			t.Fatalf("run list packages: %v", err)
		}
	})
	if !strings.Contains(output, "lodash") || !strings.Contains(output, "4.17.15") || !strings.Contains(output, "1 package found in 1 input file") {
		t.Fatalf("list packages output = %q", output)
	}
	if strings.Contains(output, "package(s)") || strings.Contains(output, "input file(s)") {
		t.Fatalf("list packages output still uses placeholder plural labels:\n%s", output)
	}
}

func TestRunSingleScanRecordsHistoryForCleanLocalScan(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:     scanDir,
		Mode:     "local",
		FailOn:   "CRITICAL",
		MaxDepth: 2,
		Timeout:  1,
		Quiet:    true,
	})
	if err != nil {
		t.Fatalf("run single scan: %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var count int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count scan history: %v", err)
	}
	if count != 1 {
		t.Fatalf("scan history rows = %d, want 1", count)
	}
}

func TestRunSingleScanPrunesHistoryOlderThanMaxAgeAfterRecording(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_HISTORY_MAX_AGE", "24h")

	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}
	seeded := []sqlite.ScanEntry{
		{RepoName: "old-repo", ScannedAt: time.Now().Add(-48 * time.Hour), PackagesCount: 1},
		{RepoName: "recent-repo", ScannedAt: time.Now().Add(-1 * time.Hour), PackagesCount: 1},
	}
	for _, entry := range seeded {
		if err := store.InsertScan(context.Background(), entry); err != nil {
			t.Fatalf("insert seeded scan history: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:     scanDir,
		Mode:     "local",
		FailOn:   "CRITICAL",
		MaxDepth: 2,
		Timeout:  1,
		Quiet:    true,
	})
	if err != nil {
		t.Fatalf("run single scan: %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var total, oldRows int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&total); err != nil {
		t.Fatalf("count scan history: %v", err)
	}
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history WHERE repo_name = 'old-repo'`).Scan(&oldRows); err != nil {
		t.Fatalf("count old scan history: %v", err)
	}
	if total != 2 || oldRows != 0 {
		t.Fatalf("scan history total=%d oldRows=%d, want total 2 with old rows pruned", total, oldRows)
	}
}

func TestRunSingleScanHistoryEnvErrorsBeforeRecording(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "unknown boolean", key: "PACKMON_HISTORY_ENABLED", value: "maybe"},
		{name: "malformed retention", key: "PACKMON_HISTORY_MAX_SCANS_PER_REPO", value: "many"},
		{name: "negative retention", key: "PACKMON_HISTORY_MAX_SCANS_PER_REPO", value: "-1"},
		{name: "malformed age retention", key: "PACKMON_HISTORY_MAX_AGE", value: "many"},
		{name: "negative age retention", key: "PACKMON_HISTORY_MAX_AGE", value: "-1h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			dbDir := t.TempDir()
			t.Setenv("PACKMON_DB_PATH", dbDir)
			t.Setenv(tt.key, tt.value)

			store, _ := newTestSQLiteStore(t, dbDir)
			if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
				t.Fatalf("set sync meta: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("close seed store: %v", err)
			}

			scanDir := filepath.Join(t.TempDir(), "empty-project")
			if err := os.MkdirAll(scanDir, 0o750); err != nil {
				t.Fatalf("mkdir scan dir: %v", err)
			}

			exitCode, err := runSingleScan(context.Background(), scanSettings{
				Path:     scanDir,
				Mode:     "local",
				FailOn:   "CRITICAL",
				MaxDepth: 2,
				Timeout:  1,
				Quiet:    true,
			})
			if err == nil {
				t.Fatal("runSingleScan() error = nil, want history env parse error")
			}
			if exitCode != ExitOperational {
				t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("runSingleScan() error = %v, want %s", err, tt.key)
			}

			verifyStore, _ := newTestSQLiteStore(t, dbDir)
			var count int
			if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
				t.Fatalf("count scan history: %v", err)
			}
			if count != 0 {
				t.Fatalf("scan history rows = %d, want 0", count)
			}
		})
	}
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set flag %s: %v", name, err)
	}
}
