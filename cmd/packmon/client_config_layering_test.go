package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// smuggledValueFixture is what an untrusted project config tries to inject. It is
// a fixture, not a credential: the whole point of the test is that it never
// survives the stripping step.
const smuggledValueFixture = "sk-not-a-real-key"

// writeUserGlobalConfig points the user-global config at a temporary home and
// writes the given YAML there.
func writeUserGlobalConfig(t *testing.T, yaml string) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packmon.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
}

// writeProjectConfig writes a repo-local .packmon.yaml into a fresh working
// directory, standing in for the untrusted config that ships with a scanned
// repository.
func writeProjectConfig(t *testing.T, yaml string) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, defaultCLIConfigFile), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}
	t.Chdir(dir)
}

// TestStripUntrustedAutoProjectFieldsClearsEveryRoutingAndCredentialField is the
// security contract behind the whole layering. `.packmon.yaml` lives in the
// repository being scanned, so it must never be able to point the CLI at another
// server, supply an API key, relax transport security, or redirect the local
// database and report output.
func TestStripUntrustedAutoProjectFieldsClearsEveryRoutingAndCredentialField(t *testing.T) {
	t.Parallel()

	allow := true
	cfg := &cliConfig{
		Server:            "https://attacker.example",
		APIKey:            smuggledValueFixture, // #nosec G101 -- fixture the test proves is stripped.
		APIKeyEnv:         "PACKMON_API_KEY",
		CACert:            "/tmp/attacker-ca.pem",
		InsecureAllowHTTP: &allow,
		RequireRemote:     &allow,
		SendRepoMetadata:  &allow,
		Webhook:           cliWebhookConfig{URL: "https://attacker.example/hook"},
		Output:            cliOutputConfig{Format: "json", File: "/tmp/exfil.json"},
		Registries:        cliRegistryConfig{NPMRegistryBaseURL: "https://attacker.example"},
		Repos: []cliRepoConfig{{
			Name:             "repo",
			Server:           "https://attacker.example",
			APIKey:           smuggledValueFixture, // #nosec G101 -- fixture the test proves is stripped.
			APIKeyEnv:        "PACKMON_API_KEY",
			SendRepoMetadata: &allow,
			Webhook:          cliWebhookConfig{URL: "https://attacker.example/hook"},
		}},
	}
	cfg.DB.Path = "/tmp/attacker.db"

	cfg.stripUntrustedAutoProjectFields()

	if cfg.Server != "" || cfg.APIKey != "" || cfg.APIKeyEnv != "" || cfg.CACert != "" {
		t.Errorf("routing/credential fields survived: %+v", cfg)
	}
	if cfg.InsecureAllowHTTP != nil {
		t.Error("InsecureAllowHTTP survived; a repo could disable transport security")
	}
	if cfg.RequireRemote != nil {
		t.Error("RequireRemote survived; a repo could force a scan mode")
	}
	if cfg.SendRepoMetadata != nil {
		t.Error("an opt-in SendRepoMetadata survived; a repo could enable metadata upload")
	}
	if cfg.Webhook != (cliWebhookConfig{}) {
		t.Errorf("Webhook survived: %+v", cfg.Webhook)
	}
	if cfg.Output != (cliOutputConfig{}) {
		t.Errorf("Output survived: %+v", cfg.Output)
	}
	if cfg.DB.Path != "" {
		t.Error("DB.Path survived; a repo could redirect the local cache")
	}
	if !reflect.DeepEqual(cfg.Registries, cliRegistryConfig{}) {
		t.Errorf("Registries survived: %+v", cfg.Registries)
	}

	repo := cfg.Repos[0]
	if repo.Server != "" || repo.APIKey != "" || repo.APIKeyEnv != "" {
		t.Errorf("per-repo routing/credential fields survived: %+v", repo)
	}
	if repo.SendRepoMetadata != nil {
		t.Error("per-repo SendRepoMetadata opt-in survived")
	}
	if repo.Webhook != (cliWebhookConfig{}) {
		t.Errorf("per-repo webhook survived: %+v", repo.Webhook)
	}
	// The repo entry itself stays: only its untrusted fields are removed.
	if repo.Name != "repo" {
		t.Errorf("repo name = %q, want the entry kept", repo.Name)
	}
}

// TestStripUntrustedAutoProjectFieldsKeepsAnOptOut covers the asymmetry in the
// metadata flag. A repository may *disable* metadata upload for itself -- that
// only reduces what leaves the machine -- but may not enable it.
func TestStripUntrustedAutoProjectFieldsKeepsAnOptOut(t *testing.T) {
	t.Parallel()

	deny := false
	cfg := &cliConfig{
		SendRepoMetadata: &deny,
		Repos:            []cliRepoConfig{{Name: "repo", SendRepoMetadata: &deny}},
	}
	cfg.stripUntrustedAutoProjectFields()

	if cfg.SendRepoMetadata == nil || *cfg.SendRepoMetadata {
		t.Error("an opt-out of metadata upload was discarded")
	}
	if cfg.Repos[0].SendRepoMetadata == nil || *cfg.Repos[0].SendRepoMetadata {
		t.Error("a per-repo opt-out of metadata upload was discarded")
	}
}

// TestLoadCLIConfigKeepsTheProjectLayerFromOverridingCredentials is the
// end-to-end version: with both layers present, the untrusted project file must
// not be able to replace the server or API key from the user-global config.
func TestLoadCLIConfigKeepsTheProjectLayerFromOverridingCredentials(t *testing.T) {
	writeUserGlobalConfig(t, `
server: https://packmon.internal
api_key: sk-user
fail_on: HIGH
`)
	writeProjectConfig(t, `
server: https://attacker.example
api_key: sk-not-a-real-key
fail_on: LOW
`)

	cfg, source, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	if cfg.Server != "https://packmon.internal" {
		t.Errorf("Server = %q, want the user-global value", cfg.Server)
	}
	if cfg.APIKey != "sk-user" {
		t.Errorf("APIKey = %q, want the user-global key", cfg.APIKey)
	}
	// A non-credential field is a legitimate project override.
	if cfg.FailOn != "LOW" {
		t.Errorf("FailOn = %q, want the project override applied", cfg.FailOn)
	}
	if !strings.HasSuffix(source, defaultCLIConfigFile) {
		t.Errorf("source = %q, want the project file reported as the last layer", source)
	}
}

// TestLoadCLIConfigCanSkipTheProjectLayer covers the opt-out used by commands
// that must not read repository-supplied configuration at all.
func TestLoadCLIConfigCanSkipTheProjectLayer(t *testing.T) {
	writeUserGlobalConfig(t, "fail_on: HIGH\n")
	writeProjectConfig(t, "fail_on: LOW\n")

	cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{SkipProjectConfig: true})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	if cfg.FailOn != "HIGH" {
		t.Errorf("FailOn = %q, want the project layer skipped", cfg.FailOn)
	}
}

// TestLoadCLIConfigReportsAnUnparseableUserConfig keeps a broken trusted config
// from being silently ignored, which would fall back to defaults and quietly
// change the scan policy.
func TestLoadCLIConfigReportsAnUnparseableUserConfig(t *testing.T) {
	writeUserGlobalConfig(t, "server: [not, a, string\n")
	writeProjectConfig(t, "fail_on: LOW\n")

	if _, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{}); err == nil {
		t.Fatal("an unparseable user config was accepted")
	}
}

// TestLoadCLIConfigReportsAnUnparseableProjectConfig is the same for the project
// layer: a malformed repo config is an error the user has to see, not a reason
// to fall back to the trusted layer alone.
func TestLoadCLIConfigReportsAnUnparseableProjectConfig(t *testing.T) {
	writeUserGlobalConfig(t, "fail_on: HIGH\n")
	writeProjectConfig(t, "fail_on: [broken\n")

	err := loadCLIConfigError(t)
	if err == nil {
		t.Fatal("an unparseable project config was accepted")
	}
	if !strings.Contains(err.Error(), defaultCLIConfigFile) {
		t.Fatalf("error = %v, want it to name the project file", err)
	}
}

// TestLoadCLIConfigRejectsUnknownKeys covers the strict decoder. A typo'd key
// that was silently ignored would leave the user believing a setting applied.
func TestLoadCLIConfigRejectsUnknownKeys(t *testing.T) {
	writeUserGlobalConfig(t, "fial_on: HIGH\n")

	if _, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{SkipProjectConfig: true}); err == nil {
		t.Fatal("a misspelled config key was accepted")
	}
}

// TestLoadCLIConfigSignalsTheAbsenceOfAnyConfigFile pins a contract callers rely
// on: with no config file anywhere the loader returns a nil config and no error.
// That is deliberately distinguishable from a present-but-empty file, which
// returns a non-nil config -- the two mean different things when deciding
// whether to warn about missing settings.
func TestLoadCLIConfigSignalsTheAbsenceOfAnyConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())

	cfg, source, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	if cfg != nil {
		t.Fatalf("config = %+v, want nil when no file exists", cfg)
	}
	if source != "" {
		t.Errorf("source = %q, want none when no file was loaded", source)
	}
}

// TestLoadCLIConfigReturnsAConfigForAnEmptyFile is the counterpart: a file that
// exists but sets nothing still counts as "configured".
func TestLoadCLIConfigReturnsAConfigForAnEmptyFile(t *testing.T) {
	writeUserGlobalConfig(t, "")
	t.Chdir(t.TempDir())

	cfg, source, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	if cfg == nil {
		t.Fatal("an existing but empty config file produced no config")
	}
	if source == "" {
		t.Error("source is empty although a file was loaded")
	}
}

// TestReadAutoProjectCLIConfigEnforcesTheSizeLimit keeps a repository from
// handing the CLI an unbounded file to parse.
func TestReadAutoProjectCLIConfigEnforcesTheSizeLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, defaultCLIConfigFile)
	oversized := strings.Repeat("#", maxAutoProjectCLIConfigFileBytes+1)
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized config: %v", err)
	}

	if _, err := readAutoProjectCLIConfig(path); err == nil {
		t.Fatal("an oversized project config was accepted")
	}

	// A file exactly at the limit is still fine.
	atLimit := strings.Repeat("#", maxAutoProjectCLIConfigFileBytes)
	if err := os.WriteFile(path, []byte(atLimit), 0o600); err != nil {
		t.Fatalf("write config at the limit: %v", err)
	}
	if _, err := readAutoProjectCLIConfig(path); err != nil {
		t.Fatalf("a config at the size limit was rejected: %v", err)
	}
}

// TestLoadExplicitCLIConfigReportsAMissingFile covers `--config` pointing at a
// path that does not exist. Falling back to the layered lookup would silently
// use a different configuration than the user asked for.
func TestLoadExplicitCLIConfigReportsAMissingFile(t *testing.T) {
	t.Parallel()

	_, _, err := loadCLIConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("a missing --config file was accepted")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want it to say the file was not found", err)
	}
}

// TestLoadExplicitCLIConfigTrustsTheGivenFile pins the difference to the project
// layer: a file the user named explicitly is trusted and keeps its credentials.
func TestLoadExplicitCLIConfigTrustsTheGivenFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "packmon.yaml")
	if err := os.WriteFile(path, []byte("server: https://packmon.internal\napi_key: sk-explicit\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, source, err := loadCLIConfig(path)
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.Server != "https://packmon.internal" || cfg.APIKey != "sk-explicit" {
		t.Fatalf("config = %+v, want the explicit file's credentials kept", cfg)
	}
	if !filepath.IsAbs(source) {
		t.Errorf("source = %q, want an absolute path", source)
	}
}

func loadCLIConfigError(t *testing.T) error {
	t.Helper()

	_, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	return err
}

// trustedRepoLayeringFixture writes a user-global config with two repositories:
// "private" opts out of repository metadata and carries trusted per-repo routing,
// "other" is untouched by the project layer. It returns both repository paths.
func trustedRepoLayeringFixture(t *testing.T) (string, string) {
	t.Helper()

	privatePath := filepath.Join(t.TempDir(), "private")
	otherPath := filepath.Join(t.TempDir(), "other")
	writeUserGlobalConfig(t, `
repos:
  - name: private
    path: `+yamlQuote(privatePath)+`
    server: https://packmon.internal
    send_repo_metadata: false
    webhook:
      url: https://hooks.internal/packmon
  - name: other
    path: `+yamlQuote(otherPath)+`
    fail_on: CRITICAL
`)
	return privatePath, otherPath
}

// yamlQuote single-quotes a value for a YAML fixture, so Windows paths with
// backslashes and drive colons stay literal.
func yamlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// TestLoadCLIConfigProjectRepoCannotReEnableATrustedRepoMetadataOptOut covers a
// project `.packmon.yaml` naming the same repository as the trusted user-global
// config. Whether the project entry omits send_repo_metadata or sets it to true
// (which the strip step turns into "unset"), the trusted opt-out must survive:
// the project layer may only restrict privacy, never re-enable metadata.
func TestLoadCLIConfigProjectRepoCannotReEnableATrustedRepoMetadataOptOut(t *testing.T) {
	cases := map[string]string{
		"omitted":     "",
		"set to true": "    send_repo_metadata: true\n",
	}
	for name, metadataLine := range cases {
		t.Run(name, func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			t.Setenv("PACKMON_NO_REPO_METADATA", "")
			privatePath, _ := trustedRepoLayeringFixture(t)
			writeProjectConfig(t, `
repos:
  - name: private
    path: `+yamlQuote(privatePath)+`
    fail_on: LOW
`+metadataLine)

			cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
			if err != nil {
				t.Fatalf("loadCLIConfigWithOptions: %v", err)
			}
			repo := cfg.findRepo("private")
			if repo == nil {
				t.Fatalf("repos = %+v, want the trusted repo kept", cfg.Repos)
			}
			if repo.SendRepoMetadata == nil || *repo.SendRepoMetadata {
				t.Fatalf("SendRepoMetadata = %v, want the trusted opt-out preserved", repo.SendRepoMetadata)
			}
			if repo.Server != "https://packmon.internal" || repo.Webhook.URL != "https://hooks.internal/packmon" {
				t.Fatalf("trusted per-repo routing lost: %+v", repo)
			}
			if repo.FailOn != "LOW" {
				t.Fatalf("FailOn = %q, want the project policy override applied", repo.FailOn)
			}

			targets, err := buildScanTargets(cfg, nil, scanFlagValues{Repo: "private"})
			if err != nil {
				t.Fatalf("buildScanTargets: %v", err)
			}
			settings, err := resolveScanSettings(newScanCmd(), cfg, targets[0], scanFlagValues{})
			if err != nil {
				t.Fatalf("resolveScanSettings: %v", err)
			}
			if !settings.OmitRepoMetadata {
				t.Fatal("OmitRepoMetadata = false, want the trusted opt-out to reach the scan")
			}
		})
	}
}

// TestLoadCLIConfigProjectRepoMatchedByPathKeepsTheTrustedOptOut covers a
// project entry that renames the repository but points at the same directory:
// renaming must not be a way around the trusted opt-out either. The project's
// name is kept.
func TestLoadCLIConfigProjectRepoMatchedByPathKeepsTheTrustedOptOut(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	privatePath, _ := trustedRepoLayeringFixture(t)
	writeProjectConfig(t, `
repos:
  - name: renamed
    path: `+yamlQuote(privatePath)+`
    send_repo_metadata: true
`)

	cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	if len(cfg.Repos) != 1 {
		t.Fatalf("repos = %+v, want only the project's repo", cfg.Repos)
	}
	repo := cfg.Repos[0]
	if repo.Name != "renamed" || !sameCLIRepoPath(repo.Path, privatePath) {
		t.Fatalf("repo = %+v, want the project's name and path kept", repo)
	}
	if repo.SendRepoMetadata == nil || *repo.SendRepoMetadata {
		t.Fatalf("SendRepoMetadata = %v, want the trusted opt-out inherited", repo.SendRepoMetadata)
	}
	if repo.Server != "https://packmon.internal" {
		t.Fatalf("Server = %q, want the trusted routing inherited", repo.Server)
	}
}

// TestLoadCLIConfigProjectReposReplaceTheTrustedList pins the layering of the
// repos list: the project's repos, in project order, replace the trusted list,
// so a trusted-only repo is not scanned by --all. A project entry that matches
// a trusted entry inherits its routing and metadata opt-out, but keeps its own
// scan policy as written.
func TestLoadCLIConfigProjectReposReplaceTheTrustedList(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_NO_REPO_METADATA", "")
	privatePath, _ := trustedRepoLayeringFixture(t)
	writeProjectConfig(t, `
repos:
  - name: app
    path: .
    mode: remote
  - name: private
    path: `+yamlQuote(privatePath)+`
`)

	cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	targets, err := buildScanTargets(cfg, nil, scanFlagValues{All: true})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	names := make([]string, 0, len(targets))
	for _, target := range targets {
		names = append(names, target.Name)
	}
	if got := strings.Join(names, ","); got != "app,private" {
		t.Fatalf("--all targets = %q, want the project's repos only, in project order", got)
	}

	private := cfg.findRepo("private")
	if private.SendRepoMetadata == nil || *private.SendRepoMetadata {
		t.Fatalf("private SendRepoMetadata = %v, want the trusted opt-out inherited", private.SendRepoMetadata)
	}
	if private.Server != "https://packmon.internal" || private.Webhook.URL != "https://hooks.internal/packmon" {
		t.Fatalf("private = %+v, want the trusted routing inherited", private)
	}
	app := cfg.findRepo("app")
	if app.Mode != "remote" || app.SendRepoMetadata != nil || app.Server != "" {
		t.Fatalf("app = %+v, want the unmatched project repo kept as written", app)
	}
}

// TestLoadCLIConfigProjectRepoNameMatchKeepsTheProjectPath covers a project
// entry that reuses a trusted repo name for another directory: the project's
// path wins (so `scan --repo private` scans what the project config says),
// while the trusted opt-out and routing are still inherited.
func TestLoadCLIConfigProjectRepoNameMatchKeepsTheProjectPath(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_NO_REPO_METADATA", "")
	trustedRepoLayeringFixture(t)
	writeProjectConfig(t, `
repos:
  - name: private
    path: .
    fail_on: LOW
`)
	projectDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	targets, err := buildScanTargets(cfg, nil, scanFlagValues{Repo: "private"})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	if !sameCLIRepoPath(targets[0].Path, projectDir) {
		t.Fatalf("--repo private path = %q, want the project path %q", targets[0].Path, projectDir)
	}
	repo := targets[0].Repo
	if repo.FailOn != "LOW" || repo.Server != "https://packmon.internal" {
		t.Fatalf("repo = %+v, want project policy plus trusted routing", repo)
	}
	settings, err := resolveScanSettings(newScanCmd(), cfg, targets[0], scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if !settings.OmitRepoMetadata {
		t.Fatal("OmitRepoMetadata = false, want the trusted opt-out inherited")
	}
}

// TestLoadCLIConfigProjectRepoAppliesEveryMatchingTrustedOptOut covers a
// project entry that takes one trusted repo's name but another trusted repo's
// path. The routing still comes from the name match, but the opt-out of the
// trusted entry that owns the directory must apply as well: otherwise reusing
// an unrestricted name would be a way around a path's send_repo_metadata: false.
func TestLoadCLIConfigProjectRepoAppliesEveryMatchingTrustedOptOut(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_NO_REPO_METADATA", "")
	privatePath, _ := trustedRepoLayeringFixture(t)
	writeProjectConfig(t, `
repos:
  - name: other
    path: `+yamlQuote(privatePath)+`
`)

	cfg, _, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{})
	if err != nil {
		t.Fatalf("loadCLIConfigWithOptions: %v", err)
	}
	repo := cfg.findRepo("other")
	if repo == nil || !sameCLIRepoPath(repo.Path, privatePath) {
		t.Fatalf("repos = %+v, want the project's name and path kept", cfg.Repos)
	}
	if repo.SendRepoMetadata == nil || *repo.SendRepoMetadata {
		t.Fatalf("SendRepoMetadata = %v, want the opt-out of the trusted entry for this path", repo.SendRepoMetadata)
	}
	if repo.Server != "" || repo.Webhook.URL != "" {
		t.Fatalf("repo = %+v, want the routing of the name match (none), not the path match", repo)
	}

	targets, err := buildScanTargets(cfg, nil, scanFlagValues{Repo: "other"})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	settings, err := resolveScanSettings(newScanCmd(), cfg, targets[0], scanFlagValues{})
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	if !settings.OmitRepoMetadata {
		t.Fatal("OmitRepoMetadata = false, want the path match's opt-out to reach the scan")
	}
}

// TestOverlayCLIReposConfigTakesRoutingFromTheNameMatch pins the routing side
// of the same case directly: name match first, then path match, while an
// opt-out from either match applies.
func TestOverlayCLIReposConfigTakesRoutingFromTheNameMatch(t *testing.T) {
	t.Parallel()

	optOut := false
	optIn := true
	dst := &cliConfig{Repos: []cliRepoConfig{
		{Name: "a", Path: filepath.FromSlash("/repos/a"), Server: "https://a.internal", SendRepoMetadata: &optIn},
		{Name: "b", Path: filepath.FromSlash("/repos/b"), Server: "https://b.internal", SendRepoMetadata: &optOut},
	}}
	overlayCLIReposConfig(dst, cliConfig{Repos: []cliRepoConfig{
		{Name: "a", Path: filepath.FromSlash("/repos/b")},
		{Name: "c", Path: filepath.FromSlash("/repos/a")},
	}})

	byName := dst.Repos[0]
	if byName.Server != "https://a.internal" {
		t.Fatalf("name+path match Server = %q, want the name match's routing", byName.Server)
	}
	if byName.SendRepoMetadata == nil || *byName.SendRepoMetadata {
		t.Fatalf("name+path match SendRepoMetadata = %v, want the path match's opt-out", byName.SendRepoMetadata)
	}
	byPath := dst.Repos[1]
	if byPath.Server != "https://a.internal" || byPath.SendRepoMetadata != nil {
		t.Fatalf("path-only match = %+v, want the path match's routing and no opt-out", byPath)
	}
}
