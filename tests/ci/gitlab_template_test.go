package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestGitLabPackmonTemplateDownloadsReleaseBinaryAtRuntime(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	variables := yamlMap(t, template["variables"], "variables")
	if _, ok := variables["PACKMON_BINARY_URL"]; ok {
		t.Fatal("PACKMON_BINARY_URL must not be precomputed in GitLab variables; shell defaults are not recursively expanded")
	}
	if got := yamlString(t, variables["PACKMON_VERSION"], "variables.PACKMON_VERSION"); got != "" {
		t.Fatalf("PACKMON_VERSION default = %q, want empty so consumers must provide an existing immutable release tag", got)
	}
	if got := yamlString(t, variables["PACKMON_ARTIFACT_EXPIRE_IN"], "variables.PACKMON_ARTIFACT_EXPIRE_IN"); got != "90 days" {
		t.Fatalf("PACKMON_ARTIFACT_EXPIRE_IN = %q, want 90 days default", got)
	}

	job := yamlMap(t, template["packmon"], "packmon")
	beforeScript := yamlStringList(t, job["before_script"], "packmon.before_script")
	joinedBeforeScript := strings.Join(beforeScript, "\n")
	if !strings.Contains(joinedBeforeScript, "set -e") {
		t.Fatal("before_script must fail on the first download or checksum error")
	}
	wantDefaultBase := `DEFAULT_BINARY_BASE_URL="https://github.com/8linkz-sec/packmon/` +
		`releases/download/${PACKMON_VERSION}"`
	if !strings.Contains(joinedBeforeScript, wantDefaultBase) {
		t.Fatalf("before_script missing runtime binary base URL default %q", wantDefaultBase)
	}
	wantMirrorDefault := `BINARY_BASE_URL="${PACKMON_BINARY_MIRROR:-${DEFAULT_BINARY_BASE_URL}}"`
	if !strings.Contains(joinedBeforeScript, wantMirrorDefault) {
		t.Fatalf("before_script missing runtime binary mirror default %q", wantMirrorDefault)
	}
	if strings.Contains(joinedBeforeScript, "releases/latest/download") {
		t.Fatal("GitLab template must not download Packmon from a mutable latest release URL")
	}
	for _, want := range []string{
		`case "$PACKMON_VERSION" in`,
		`BINARY_BASE_URL="${BINARY_BASE_URL%/}"`,
		`BINARY_NAME="packmon-linux-${ARCH}"`,
		`BINARY_URL="${BINARY_BASE_URL}/${BINARY_NAME}"`,
		`CHECKSUM_URL="${BINARY_BASE_URL}/checksums.txt"`,
	} {
		if !strings.Contains(joinedBeforeScript, want) {
			t.Fatalf("before_script missing %q", want)
		}
	}
	if !strings.Contains(joinedBeforeScript, `curl ${CURL_FLAGS} "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`) {
		t.Fatal("before_script must fail fast when downloading the release binary fails")
	}
	if !strings.Contains(joinedBeforeScript, `sha256sum -c "${BINARY_NAME}.sha256"`) {
		t.Fatal("before_script must verify the downloaded binary checksum before installing it")
	}
	assertSubstringOrder(t, joinedBeforeScript, `sha256sum -c "${BINARY_NAME}.sha256"`, `mv "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`)
	if !strings.Contains(joinedBeforeScript, "packmon version") {
		t.Fatal("before_script must execute the downloaded binary before scanning")
	}
}

func TestGitLabPackmonTemplatePinsRunnerImageByDigest(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	image := yamlString(t, job["image"], "packmon.image")
	if !strings.HasPrefix(image, "alpine:3.23@sha256:") {
		t.Fatalf("packmon.image = %q, want alpine:3.23 pinned by digest", image)
	}
	if image == "alpine:3.23" {
		t.Fatal("GitLab template runner image must not be tag-only")
	}
}

func TestGitLabPackmonTemplateVerifiesReleaseBinaryAttestationBeforeInstall(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	beforeScript := strings.Join(yamlStringList(t, job["before_script"], "packmon.before_script"), "\n")
	for _, want := range []string{
		"apk add --no-cache \\",
		"curl=8.19.0-r0",
		"jq=1.8.1-r0",
		"cosign=2.6.3-r1",
		"github-cli=2.83.0-r6",
		`gh attestation verify "/tmp/${BINARY_NAME}"`,
		"--repo 8linkz-sec/packmon",
		"--signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml",
		`--source-ref "refs/tags/${PACKMON_VERSION}"`,
	} {
		if !strings.Contains(beforeScript, want) {
			t.Fatalf("before_script missing release binary attestation marker %q", want)
		}
	}
	assertSubstringOrder(t, beforeScript, `sha256sum -c "${BINARY_NAME}.sha256"`, `gh attestation verify "/tmp/${BINARY_NAME}"`)
	assertSubstringOrder(t, beforeScript, `gh attestation verify "/tmp/${BINARY_NAME}"`, `mv "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`)
	assertSubstringOrder(t, beforeScript, `gh attestation verify "/tmp/${BINARY_NAME}"`, "packmon version")
}

func TestGitLabPackmonTemplatePinsAlpinePackageInstalls(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	beforeScript := strings.Join(yamlStringList(t, job["before_script"], "packmon.before_script"), "\n")
	assertApkPackagesPinned(t, "ci/gitlab/.packmon-scan.yml before_script", beforeScript, []string{
		"curl",
		"jq",
		"cosign",
		"github-cli",
	})
}

func TestGitLabPackmonTemplateUsesBoundedCurlDownloads(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	beforeScript := strings.Join(yamlStringList(t, job["before_script"], "packmon.before_script"), "\n")
	for _, want := range []string{
		`CURL_FLAGS="--fail --show-error --location --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 10 --max-time 120"`,
		`curl ${CURL_FLAGS} "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`,
		`curl ${CURL_FLAGS} "${CHECKSUM_URL}" -o /tmp/packmon-checksums.txt`,
	} {
		if !strings.Contains(beforeScript, want) {
			t.Fatalf("before_script missing bounded curl marker %q", want)
		}
	}
}

func TestGitLabPackmonTemplatePublishesExpectedReports(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")

	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")
	for _, want := range []string{
		`--mode remote`,
		`--server "$PACKMON_SERVER"`,
		`--no-project-config`,
		`--output-json results.json`,
		`--output-junit results.xml`,
		`--output-sarif results.sarif`,
		`-- "$PACKMON_SCAN_PATH"`,
		`exit $EXIT_CODE`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("packmon.script missing %q", want)
		}
	}
	if strings.Contains(script, `packmon scan "$PACKMON_SCAN_PATH"`) {
		t.Fatal("PACKMON_SCAN_PATH must not appear before fixed scan flags")
	}
	assertSubstringOrder(t, script, `--output-sarif results.sarif`, `-- "$PACKMON_SCAN_PATH"`)

	artifacts := yamlMap(t, job["artifacts"], "packmon.artifacts")
	if got := yamlString(t, artifacts["when"], "packmon.artifacts.when"); got != "always" {
		t.Fatalf("artifacts.when = %q, want always", got)
	}
	paths := yamlStringList(t, artifacts["paths"], "packmon.artifacts.paths")
	for _, want := range []string{"results.json", "results.xml", "results.sarif"} {
		if !contains(paths, want) {
			t.Fatalf("artifacts.paths missing %q", want)
		}
	}
	reports := yamlMap(t, artifacts["reports"], "packmon.artifacts.reports")
	if got := yamlString(t, reports["junit"], "packmon.artifacts.reports.junit"); got != "results.xml" {
		t.Fatalf("junit report = %q, want results.xml", got)
	}
	if got := yamlString(t, artifacts["expire_in"], "packmon.artifacts.expire_in"); got != "$PACKMON_ARTIFACT_EXPIRE_IN" {
		t.Fatalf("artifacts.expire_in = %q, want $PACKMON_ARTIFACT_EXPIRE_IN", got)
	}
}

func TestGitLabPackmonTemplateSurfacesDegradedFeedHealth(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")
	for _, want := range []string{
		"feed_status",
		"db_stale",
		"db_age_days",
		"Packmon feed status:",
		"Packmon local DB stale:",
		"Packmon local DB age days:",
		"Packmon scan coverage degraded",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("packmon.script missing degraded feed marker %q", want)
		}
	}
}

func TestGitLabPackmonTemplateValidatesScanPathBeforeScan(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")
	for _, want := range []string{
		`case "$PACKMON_SCAN_PATH" in`,
		`""|/*|-*|*..*)`,
		`grep -q '[[:cntrl:]]'`,
		`scan path must be a non-empty relative path without parent traversal or leading dash`,
		`-- "$PACKMON_SCAN_PATH"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("packmon.script missing scan path guard %q", want)
		}
	}
	assertSubstringOrder(t, script, `case "$PACKMON_SCAN_PATH" in`, `packmon scan \`)
	assertSubstringOrder(t, script, `grep -q '[[:cntrl:]]'`, `packmon scan \`)
}

func TestGitLabPackmonTemplateSignsResultArtifacts(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	idTokens := yamlMap(t, job["id_tokens"], "packmon.id_tokens")
	sigstore := yamlMap(t, idTokens["SIGSTORE_ID_TOKEN"], "packmon.id_tokens.SIGSTORE_ID_TOKEN")
	if got := yamlString(t, sigstore["aud"], "SIGSTORE_ID_TOKEN.aud"); got != "sigstore" {
		t.Fatalf("SIGSTORE_ID_TOKEN.aud = %q, want sigstore", got)
	}

	beforeScript := strings.Join(yamlStringList(t, job["before_script"], "packmon.before_script"), "\n")
	if !strings.Contains(beforeScript, "apk add --no-cache \\") ||
		!strings.Contains(beforeScript, "cosign=2.6.3-r1") {
		t.Fatal("before_script must install cosign before signing GitLab result artifacts")
	}

	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")
	for _, want := range []string{
		`for artifact in results.json results.xml results.sarif; do`,
		`sha256sum $RESULT_ARTIFACTS > results.sha256`,
		`cosign sign-blob --yes --bundle results.sigstore.json results.sha256`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("packmon.script missing result signing marker %q", want)
		}
	}

	artifacts := yamlMap(t, job["artifacts"], "packmon.artifacts")
	paths := yamlStringList(t, artifacts["paths"], "packmon.artifacts.paths")
	for _, want := range []string{"results.sha256", "results.sigstore.json"} {
		if !contains(paths, want) {
			t.Fatalf("artifacts.paths missing signed integrity artifact %q", want)
		}
	}
}

func TestGitLabPackmonTemplateShellBlocksAreSyntacticallyValid(t *testing.T) {
	t.Parallel()

	sh := gitLabTemplateShell(t)

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	for _, block := range []struct {
		name string
		body string
	}{
		{"before_script", strings.Join(yamlStringList(t, job["before_script"], "packmon.before_script"), "\n")},
		{"script", strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")},
	} {
		cmd := exec.Command(sh, "-n") // #nosec G204 -- test uses the located system shell to syntax-check static template snippets.
		cmd.Stdin = strings.NewReader(block.body)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s shell syntax invalid: %v\n%s", block.name, err, out)
		}
	}
}

func TestGitLabPackmonTemplateScriptMapsExitCodeThreeToSuccess(t *testing.T) {
	t.Parallel()

	sh := gitLabTemplateShell(t)

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	writeExecutable(t, filepath.Join(binDir, "packmon"), `#!/bin/sh
json=""
junit=""
sarif=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-json) shift; json="$1" ;;
    --output-junit) shift; junit="$1" ;;
    --output-sarif) shift; sarif="$1" ;;
  esac
  shift
done
[ -n "$json" ] && printf '{"packages_scanned":1,"findings_count":1}\n' > "$json"
[ -n "$junit" ] && printf '<testsuite></testsuite>\n' > "$junit"
[ -n "$sarif" ] && printf '{"version":"2.1.0"}\n' > "$sarif"
exit 3
`)
	writeExecutable(t, filepath.Join(binDir, "jq"), `#!/bin/sh
cat >/dev/null
printf 'Packages scanned: 1, Findings: 1\n'
`)
	writeExecutable(t, filepath.Join(binDir, "cosign"), `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) shift; bundle="$1" ;;
  esac
  shift
done
[ -n "$bundle" ] && printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json"}\n' > "$bundle"
`)

	cmd := exec.Command(sh, "-c", script) // #nosec G204 -- test executes a static repository template with fake tools in t.TempDir.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PACKMON_SCAN_PATH=.",
		"PACKMON_FAIL_ON=CRITICAL",
		"PACKMON_SERVER=https://packmon.example.test",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GitLab script returned error: %v\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{
		"Packmon exit code: 3",
		"Packages scanned: 1, Findings: 1",
		"Findings below blocking threshold; pipeline stays green.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("GitLab script output missing %q:\n%s", want, output)
		}
	}
	for _, want := range []string{"results.json", "results.xml", "results.sarif", "results.sha256", "results.sigstore.json"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Fatalf("expected %s to be written: %v", want, err)
		}
	}
}

func TestGitLabPackmonTemplateScriptRejectsLeadingDashScanPath(t *testing.T) {
	t.Parallel()

	sh := gitLabTemplateShell(t)

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	writeExecutable(t, filepath.Join(binDir, "packmon"), `#!/bin/sh
printf 'packmon was invoked\n' > packmon-called
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "jq"), `#!/bin/sh
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "cosign"), `#!/bin/sh
exit 0
`)

	cmd := exec.Command(sh, "-c", script) // #nosec G204 -- test executes a static repository template with fake tools in t.TempDir.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PACKMON_SCAN_PATH=--list-packages",
		"PACKMON_FAIL_ON=CRITICAL",
		"PACKMON_SERVER=https://packmon.example.test",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("GitLab script accepted a leading-dash PACKMON_SCAN_PATH:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "packmon-called")); !os.IsNotExist(statErr) {
		t.Fatalf("packmon must not be invoked for a leading-dash PACKMON_SCAN_PATH; stat err=%v", statErr)
	}
	if !strings.Contains(string(out), "scan path must be a non-empty relative path without parent traversal or leading dash") {
		t.Fatalf("GitLab script output missing scan path validation error:\n%s", out)
	}
}

func TestGitLabPackmonTemplateScriptSurfacesDegradedFeedHealth(t *testing.T) {
	t.Parallel()

	sh := gitLabTemplateShell(t)

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")
	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	writeExecutable(t, filepath.Join(binDir, "packmon"), `#!/bin/sh
json=""
junit=""
sarif=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-json) shift; json="$1" ;;
    --output-junit) shift; junit="$1" ;;
    --output-sarif) shift; sarif="$1" ;;
  esac
  shift
done
[ -n "$json" ] && printf '{"packages_scanned":1,"findings_count":0,"feed_status":"degraded","db_stale":true,"db_age_days":14}\n' > "$json"
[ -n "$junit" ] && printf '<testsuite></testsuite>\n' > "$junit"
[ -n "$sarif" ] && printf '{"version":"2.1.0"}\n' > "$sarif"
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "jq"), `#!/bin/sh
if [ "$1" = "-r" ]; then
  shift
fi
query="$1"
case "$query" in
  *packages_scanned*) printf 'Packages scanned: 1, Findings: 0\n' ;;
  *feed_status*) printf 'degraded\n' ;;
  *db_stale*) printf 'true\n' ;;
  *db_age_days*) printf '14\n' ;;
  *) printf '\n' ;;
esac
`)
	writeExecutable(t, filepath.Join(binDir, "cosign"), `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) shift; bundle="$1" ;;
  esac
  shift
done
[ -n "$bundle" ] && printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json"}\n' > "$bundle"
`)

	cmd := exec.Command(sh, "-c", script) // #nosec G204 -- test executes a static repository template with fake tools in t.TempDir.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PACKMON_SCAN_PATH=.",
		"PACKMON_FAIL_ON=CRITICAL",
		"PACKMON_SERVER=https://packmon.example.test",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GitLab script returned error: %v\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{
		"Packmon feed status: degraded",
		"Packmon local DB stale: true",
		"Packmon local DB age days: 14",
		"Packmon scan coverage degraded",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("GitLab script output missing %q:\n%s", want, output)
		}
	}
}

func loadGitLabTemplate(t *testing.T) map[string]any {
	t.Helper()

	path := filepath.Join("..", "..", "ci", "gitlab", ".packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read GitLab template: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse GitLab template YAML: %v", err)
	}
	return doc
}

func yamlMap(t *testing.T, value any, name string) map[string]any {
	t.Helper()

	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s has type %T, want map", name, value)
	}
	return m
}

func yamlString(t *testing.T, value any, name string) string {
	t.Helper()

	s, ok := value.(string)
	if !ok {
		t.Fatalf("%s has type %T, want string", name, value)
	}
	return s
}

func yamlStringList(t *testing.T, value any, name string) []string {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s has type %T, want list", name, value)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s[%d] has type %T, want string", name, i, item)
		}
		out = append(out, s)
	}
	return out
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func assertApkPackagesPinned(t *testing.T, source, text string, packageNames []string) {
	t.Helper()

	normalized := regexp.MustCompile(`\\\r?\n\s*`).ReplaceAllString(text, " ")
	apkAddRE := regexp.MustCompile(`apk\s+add\s+--no-cache\s+([^&;\r\n]+)`)
	versionPinRE := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
	found := make(map[string]bool, len(packageNames))

	for _, match := range apkAddRE.FindAllStringSubmatch(normalized, -1) {
		for _, token := range strings.Fields(match[1]) {
			token = strings.Trim(token, `"'`)
			if token == "" || strings.HasPrefix(token, "-") {
				continue
			}
			for _, packageName := range packageNames {
				if token == packageName {
					t.Fatalf("%s installs Alpine package %q without an exact version pin", source, packageName)
				}
				if !strings.HasPrefix(token, packageName+"=") {
					continue
				}
				found[packageName] = true
				version := strings.TrimPrefix(token, packageName+"=")
				if !versionPinRE.MatchString(version) {
					t.Fatalf("%s installs Alpine package %q with non-exact pin %q; want name=version-rN", source, packageName, token)
				}
			}
		}
	}

	for _, packageName := range packageNames {
		if !found[packageName] {
			t.Fatalf("%s does not install expected Alpine package %q with name=version-rN", source, packageName)
		}
	}
}

func gitLabTemplateShell(t *testing.T) string {
	t.Helper()

	if sh, err := exec.LookPath("sh"); err == nil {
		return sh
	}
	for _, candidate := range []string{
		`C:\Program Files\Git\bin\sh.exe`,
		`C:\Program Files (x86)\Git\bin\sh.exe`,
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("sh not available")
	return ""
}

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- test helper writes fake executables in t.TempDir.
		t.Fatalf("write executable %s: %v", path, err)
	}
}
