package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const patchedGoVersion = "1.26.4"

func TestBuildToolchainPinsPatchedGoVersion(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	wantBuildImage := "FROM golang:" + patchedGoVersion + "-alpine@sha256:"
	dockerText := string(dockerData)
	if !strings.Contains(dockerText, wantBuildImage) || !strings.Contains(dockerText, " AS build") {
		t.Fatalf("Dockerfile must pin golang:%s-alpine by digest in the build stage", patchedGoVersion)
	}

	for _, rel := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "nightly.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, `go-version: "1.26"`) || strings.Contains(text, `go: ["1.26"]`) {
			t.Fatalf("%s still uses an unpinned Go minor version", rel)
		}
		if !strings.Contains(text, patchedGoVersion) {
			t.Fatalf("%s does not reference patched Go version %s", rel, patchedGoVersion)
		}
	}
}

func TestDockerRuntimeStagesUseCurrentAlpine(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"FROM alpine:3.24 AS server",
		"FROM alpine:3.24 AS cli",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile missing runtime stage %q", want)
		}
	}
	if strings.Contains(dockerText, "FROM alpine:3.23") {
		t.Fatal("Dockerfile still uses alpine:3.23 in a runtime stage")
	}
}

func TestGitHubReleaseDockerBuildTargetsServerStage(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	for _, step := range wf.Jobs["release"].Steps {
		if strings.Contains(step.Uses, "docker/build-push-action") {
			if step.With["target"] != "server" {
				t.Fatalf("release Docker build target = %q, want server", step.With["target"])
			}
			return
		}
	}
	t.Fatal("release workflow has no docker/build-push-action step")
}

func TestGitHubCIWorkflowRunsTaggedIntegrationTests(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Name  string `yaml:"name"`
			Needs any    `yaml:"needs"`
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	for key, job := range wf.Jobs {
		if key != "integration" && !strings.Contains(strings.ToLower(job.Name), "integration") {
			continue
		}
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "make test-integration") {
				return
			}
		}
		t.Fatalf("integration job %q does not run make test-integration", key)
	}
	t.Fatal("ci workflow has no integration job")
}

func TestMakeTestTargetsSetGOTMPDIR(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "Makefile")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"GOTMPDIR ?= $(CURDIR)/.gotmp",
		`mkdir -p "$(GOTMPDIR)"`,
		`GOTMPDIR="$(GOTMPDIR)" go test -race`,
		`GOTMPDIR="$(GOTMPDIR)" go test ./tests/ci`,
		`GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -tags integration`,
		`GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -tags e2e`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Makefile missing %q", want)
		}
	}
}

func TestHelmChartRequiresNonDefaultAdminBootstrapPassword(t *testing.T) {
	t.Parallel()

	valuesPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "values.yaml")
	valuesData, err := os.ReadFile(valuesPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var values struct {
		Admin struct {
			InitialPassword string `yaml:"initialPassword"`
		} `yaml:"admin"`
	}
	if err := yaml.Unmarshal(valuesData, &values); err != nil {
		t.Fatalf("parse values.yaml: %v", err)
	}
	if values.Admin.InitialPassword != "" {
		t.Fatalf("admin.initialPassword default = %q, want empty required override", values.Admin.InitialPassword)
	}

	helpersPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "templates", "_helpers.tpl")
	helpersData, err := os.ReadFile(helpersPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read _helpers.tpl: %v", err)
	}
	helpers := string(helpersData)
	for _, want := range []string{"packmon.validateAdminPassword", "required", "change-me"} {
		if !strings.Contains(helpers, want) {
			t.Fatalf("_helpers.tpl missing admin-password validation marker %q", want)
		}
	}

	secretPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "templates", "secret.yaml")
	secretData, err := os.ReadFile(secretPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read secret.yaml: %v", err)
	}
	if !strings.Contains(string(secretData), `include "packmon.validateAdminPassword"`) {
		t.Fatal("secret.yaml must include packmon.validateAdminPassword before rendering the admin secret")
	}
}

func TestHelmAndRancherProductionDefaultsAreHardened(t *testing.T) {
	t.Parallel()

	valuesPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "values.yaml")
	valuesData, err := os.ReadFile(valuesPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	valuesText := string(valuesData)
	for _, forbidden := range []string{"tag: latest", "postgres:16-alpine", "resources: {}"} {
		if strings.Contains(valuesText, forbidden) {
			t.Fatalf("values.yaml contains soft default %q", forbidden)
		}
	}
	for _, want := range []string{
		`tag: "0.5.0"`,
		"image: postgres:18-alpine",
		"encryptionKey:",
		"trustedProxies:",
		"allowInsecureLocalHTTP:",
		"tls:",
		"podSecurityContext:",
		"containerSecurityContext:",
		"postgresqlSecurityContext:",
	} {
		if !strings.Contains(valuesText, want) {
			t.Fatalf("values.yaml missing %q", want)
		}
	}

	for _, rel := range []string{
		filepath.Join("deploy", "helm", "packmon", "templates", "deployment.yaml"),
		filepath.Join("deploy", "helm", "packmon", "templates", "postgres-statefulset.yaml"),
		filepath.Join("deploy", "helm", "packmon", "templates", "cronjob-backup.yaml"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, want := range []string{"securityContext:", "resources:"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q", rel, want)
			}
		}
	}

	configMapPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "templates", "configmap.yaml")
	configMapData, err := os.ReadFile(configMapPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read configmap.yaml: %v", err)
	}
	configMapText := string(configMapData)
	for _, want := range []string{
		"PACKMON_FEED_ENDOFLIFE_ENABLED",
		"PACKMON_FEED_REVERSINGLABS_ENABLED",
		"PACKMON_FEED_NVD_ENABLED",
		"PACKMON_TRUSTED_PROXIES",
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP",
		"PACKMON_TLS_CERT_FILE",
		"PACKMON_TLS_KEY_FILE",
	} {
		if !strings.Contains(configMapText, want) {
			t.Fatalf("configmap.yaml missing %q", want)
		}
	}

	secretPath := filepath.Join("..", "..", "deploy", "helm", "packmon", "templates", "secret.yaml")
	secretData, err := os.ReadFile(secretPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read secret.yaml: %v", err)
	}
	secretText := string(secretData)
	for _, want := range []string{
		`include "packmon.validateEncryptionKey"`,
		`include "packmon.validateTransportSecurity"`,
		"encryption-key:",
		"nvd-api-key:",
		"reversinglabs-api-key:",
	} {
		if !strings.Contains(secretText, want) {
			t.Fatalf("secret.yaml missing %q", want)
		}
	}

	rancherPath := filepath.Join("..", "..", "deploy", "rancher", "values.production.yaml")
	rancherData, err := os.ReadFile(rancherPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read rancher values: %v", err)
	}
	rancherText := string(rancherData)
	for _, forbidden := range []string{"tag: latest", "postgres:16-alpine"} {
		if strings.Contains(rancherText, forbidden) {
			t.Fatalf("Rancher values contain soft default %q", forbidden)
		}
	}
	for _, want := range []string{`tag: "0.5.0"`, "encryptionKey:", "trustedProxies:", "postgres:18-alpine"} {
		if !strings.Contains(rancherText, want) {
			t.Fatalf("Rancher values missing %q", want)
		}
	}
}
