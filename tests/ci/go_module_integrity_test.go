package ci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

type moduleSumRecords struct {
	content string
	goMod   string
}

type moduleDownload struct {
	Path     string
	Version  string
	Info     string
	GoMod    string
	Zip      string
	Sum      string
	GoModSum string
	Error    string
}

func TestSelectedYAMLModuleHasContentAndModChecksums(t *testing.T) {
	selected := selectedYAMLRequirement(t)
	records := selectedModuleSumRecords(t, selected)

	assertH1SHA256(t, selected.String(), records.content)
	assertH1SHA256(t, selected.String()+"/go.mod", records.goMod)
}

func TestSelectedYAMLModuleVerifiesFromCleanOfflineProxyAndRejectsCorruption(t *testing.T) {
	selected := selectedYAMLRequirement(t)
	records := selectedModuleSumRecords(t, selected)
	repoRoot := repositoryRoot(t)

	seedOutput, seedErr := runIsolatedGoCommand(t, repoRoot, nil, "mod", "download", "-json", selected.String())
	if seedErr != nil {
		t.Fatalf("seed clean YAML module download: %v\n%s", seedErr, seedOutput)
	}
	seed := decodeModuleDownload(t, seedOutput)
	if seed.Path != selected.Path || seed.Version != selected.Version {
		t.Fatalf("downloaded module = %s@%s, want %s", seed.Path, seed.Version, selected.String())
	}
	if seed.Error != "" {
		t.Fatalf("download reported an error: %s", seed.Error)
	}
	if seed.Sum != records.content || seed.GoModSum != records.goMod {
		t.Fatalf("downloaded sums = (%q, %q), want tracked (%q, %q)", seed.Sum, seed.GoModSum, records.content, records.goMod)
	}

	proxyRoot := t.TempDir()
	writeModuleProxy(t, proxyRoot, selected, seed.Info, seed.GoMod, seed.Zip)
	consumer := newModuleConsumer(t, repoRoot)
	offline := offlineProxyEnvironment(t, proxyRoot)
	verifiedOutput, verifiedErr := runIsolatedGoCommand(t, consumer, offline, "mod", "download", "-json", selected.String())
	if verifiedErr != nil {
		t.Fatalf("verify selected module from clean offline proxy: %v\n%s", verifiedErr, verifiedOutput)
	}
	verified := decodeModuleDownload(t, verifiedOutput)
	if verified.Error != "" || verified.Sum != records.content || verified.GoModSum != records.goMod {
		t.Fatalf("offline verification = error %q sums (%q, %q), want no error and (%q, %q)", verified.Error, verified.Sum, verified.GoModSum, records.content, records.goMod)
	}

	corruptZip := rebuildCorruptModuleZip(t, selected, seed.Zip)
	checked, err := modzip.CheckZip(selected, corruptZip)
	if err != nil {
		t.Fatalf("rebuilt corrupt fixture is not a structurally valid module zip: %v (%+v)", err, checked)
	}
	corruptSum, err := dirhash.HashZip(corruptZip, dirhash.Hash1)
	if err != nil {
		t.Fatalf("hash corrupt module zip: %v", err)
	}
	if corruptSum == records.content {
		t.Fatalf("corrupt module zip retained tracked content checksum %s", records.content)
	}

	corruptProxyRoot := t.TempDir()
	writeModuleProxy(t, corruptProxyRoot, selected, seed.Info, seed.GoMod, corruptZip)
	corruptConsumer := newModuleConsumer(t, repoRoot)
	corruptOutput, corruptErr := runIsolatedGoCommand(t, corruptConsumer, offlineProxyEnvironment(t, corruptProxyRoot), "mod", "download", selected.String())
	if corruptErr == nil {
		t.Fatalf("corrupt YAML module unexpectedly passed checksum verification\n%s", corruptOutput)
	}
	lowerOutput := strings.ToLower(corruptOutput)
	for _, marker := range []string{"checksum mismatch", "security error"} {
		if !strings.Contains(lowerOutput, marker) {
			t.Fatalf("corrupt module failure missing %q marker: %v\n%s", marker, corruptErr, corruptOutput)
		}
	}
}

func selectedYAMLRequirement(t *testing.T) module.Version {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	parsed, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == maintainedYAMLModule {
			if requirement.Indirect {
				t.Fatalf("%s must remain a direct dependency", maintainedYAMLModule)
			}
			return requirement.Mod
		}
	}
	t.Fatalf("go.mod does not select %s", maintainedYAMLModule)
	return module.Version{}
}

func selectedModuleSumRecords(t *testing.T, selected module.Version) moduleSumRecords {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "go.sum"))
	if err != nil {
		t.Fatalf("read go.sum: %v", err)
	}
	wanted := map[string]*string{
		selected.Version:             nil,
		selected.Version + "/go.mod": nil,
	}
	values := make(map[string]string, len(wanted))
	for lineIndex, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != selected.Path {
			continue
		}
		if len(fields) != 3 {
			t.Fatalf("go.sum line %d for %s has %d fields, want 3", lineIndex+1, selected.Path, len(fields))
		}
		if _, required := wanted[fields[1]]; !required {
			continue
		}
		if previous, duplicate := values[fields[1]]; duplicate {
			t.Fatalf("go.sum has duplicate %s %s records (%q and %q)", selected.Path, fields[1], previous, fields[2])
		}
		values[fields[1]] = fields[2]
	}
	content, contentOK := values[selected.Version]
	goMod, goModOK := values[selected.Version+"/go.mod"]
	if !contentOK || !goModOK {
		t.Fatalf("go.sum must contain exactly the selected %s content and go.mod records; content=%t go.mod=%t", selected.String(), contentOK, goModOK)
	}
	return moduleSumRecords{content: content, goMod: goMod}
}

func assertH1SHA256(t *testing.T, label, checksum string) {
	t.Helper()

	if !strings.HasPrefix(checksum, "h1:") {
		t.Fatalf("%s checksum %q must use h1", label, checksum)
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(checksum, "h1:"))
	if err != nil {
		t.Fatalf("%s checksum %q is not valid base64: %v", label, checksum, err)
	}
	if len(digest) != 32 {
		t.Fatalf("%s checksum decodes to %d bytes, want SHA-256 length 32", label, len(digest))
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func canonicalFileURL(t *testing.T, path string) string {
	t.Helper()

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve file URL path %s: %v", path, err)
	}
	slashPath := filepath.ToSlash(abs)
	if filepath.VolumeName(abs) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	return (&url.URL{Scheme: "file", Host: "", Path: slashPath}).String()
}

func decodeModuleDownload(t *testing.T, output string) moduleDownload {
	t.Helper()

	var downloaded moduleDownload
	if err := json.Unmarshal([]byte(output), &downloaded); err != nil {
		t.Fatalf("decode go mod download JSON: %v\n%s", err, output)
	}
	return downloaded
}

func writeModuleProxy(t *testing.T, root string, selected module.Version, infoPath, modPath, zipPath string) {
	t.Helper()

	escapedPath, err := module.EscapePath(selected.Path)
	if err != nil {
		t.Fatalf("escape module path: %v", err)
	}
	escapedVersion, err := module.EscapeVersion(selected.Version)
	if err != nil {
		t.Fatalf("escape module version: %v", err)
	}
	versionDir := filepath.Join(root, filepath.FromSlash(escapedPath), "@v")
	if err := os.MkdirAll(versionDir, 0o700); err != nil {
		t.Fatalf("create local module proxy: %v", err)
	}
	for extension, source := range map[string]string{
		".info": infoPath,
		".mod":  modPath,
		".zip":  zipPath,
	} {
		data, readErr := os.ReadFile(source) //nolint:gosec // paths are emitted by the local Go tool or created by this test.
		if readErr != nil {
			t.Fatalf("read module proxy source %s: %v", source, readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(versionDir, escapedVersion+extension), data, 0o600); writeErr != nil { //nolint:gosec // destination is below a test-owned proxy and uses x/mod-escaped module coordinates.
			t.Fatalf("write module proxy %s fixture: %v", extension, writeErr)
		}
	}
}

func newModuleConsumer(t *testing.T, repoRoot string) string {
	t.Helper()

	consumer := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(repoRoot, name)) //nolint:gosec // fixed tracked repository manifests.
		if err != nil {
			t.Fatalf("read tracked %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(consumer, name), data, 0o600); err != nil { //nolint:gosec // destination is a fixed manifest name below a test-owned directory.
			t.Fatalf("copy tracked %s to isolated consumer: %v", name, err)
		}
	}
	return consumer
}

func offlineProxyEnvironment(t *testing.T, proxyRoot string) map[string]string {
	t.Helper()

	return map[string]string{
		"GOPROXY":   canonicalFileURL(t, proxyRoot),
		"GONOPROXY": "none",
		"GOPRIVATE": "",
		"GONOSUMDB": "",
		"GOSUMDB":   "off",
		"GOVCS":     "off",
	}
}

func rebuildCorruptModuleZip(t *testing.T, selected module.Version, originalZip string) string {
	t.Helper()

	extracted := filepath.Join(t.TempDir(), "module")
	if err := modzip.Unzip(extracted, selected, originalZip); err != nil {
		t.Fatalf("extract original module zip: %v", err)
	}
	var candidates []string
	err := filepath.WalkDir(extracted, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() || strings.EqualFold(entry.Name(), "go.mod") {
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})
	if err != nil {
		t.Fatalf("enumerate extracted module: %v", err)
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		t.Fatal("downloaded module has no regular non-go.mod file to corrupt")
	}
	target := candidates[0]
	data, err := os.ReadFile(target) //nolint:gosec // deterministic file within a test-owned extraction directory.
	if err != nil {
		t.Fatalf("read corruption target: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat corruption target: %v", err)
	}
	if err := os.Chmod(target, info.Mode()|0o200); err != nil {
		t.Fatalf("make corruption target writable: %v", err)
	}
	if err := os.WriteFile(target, append(data, []byte("\npackmon checksum corruption fixture\n")...), 0o600); err != nil { //nolint:gosec // target was enumerated inside the test-owned extraction directory.
		t.Fatalf("mutate corruption target: %v", err)
	}

	corruptZip := filepath.Join(t.TempDir(), "corrupt.zip")
	file, err := os.Create(corruptZip) //nolint:gosec // fixed filename inside a test-owned temporary directory.
	if err != nil {
		t.Fatalf("create corrupt module zip: %v", err)
	}
	createErr := modzip.CreateFromDir(file, selected, extracted)
	closeErr := file.Close()
	if createErr != nil {
		t.Fatalf("rebuild corrupt module zip: %v", createErr)
	}
	if closeErr != nil {
		t.Fatalf("close corrupt module zip: %v", closeErr)
	}
	return corruptZip
}

func runIsolatedGoCommand(t *testing.T, dir string, overrides map[string]string, args ...string) (string, error) {
	t.Helper()

	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate local Go toolchain: %v", err)
	}
	isolationRoot := t.TempDir()
	baseOverrides := map[string]string{
		"CGO_ENABLED": "0",
		"GOCACHE":     filepath.Join(isolationRoot, "build-cache"),
		"GOENV":       "off",
		"GOFLAGS":     "-mod=readonly",
		"GOMODCACHE":  filepath.Join(isolationRoot, "module-cache"),
		"GOPATH":      filepath.Join(isolationRoot, "gopath"),
		"GOTMPDIR":    filepath.Join(isolationRoot, "tmp"),
		"GOTOOLCHAIN": "local",
		"GOWORK":      "off",
	}
	for key, value := range overrides {
		baseOverrides[key] = value
	}
	for _, path := range []string{baseOverrides["GOCACHE"], baseOverrides["GOMODCACHE"], baseOverrides["GOPATH"], baseOverrides["GOTMPDIR"]} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create isolated Go directory %s: %v", path, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBinary, args...) // #nosec G204 -- test invokes the explicitly resolved Go tool with fixed test arguments.
	cmd.Dir = dir
	cmd.Env = sanitizedEnvironment(baseOverrides)
	output, runErr := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(output), fmt.Errorf("go %s timed out after 2m", strings.Join(args, " "))
	}
	return string(output), runErr
}

func sanitizedEnvironment(overrides map[string]string) []string {
	blocked := make(map[string]struct{}, len(overrides)+16)
	for _, key := range []string{
		"CGO_ENABLED",
		"GOCACHE",
		"GOENV",
		"GOFLAGS",
		"GOMODCACHE",
		"GONOPROXY",
		"GOPATH",
		"GOPRIVATE",
		"GOPROXY",
		"GONOSUMDB",
		"GOSUMDB",
		"GOTMPDIR",
		"GOTOOLCHAIN",
		"GOVCS",
		"GOWORK",
	} {
		blocked[key] = struct{}{}
	}
	for key := range overrides {
		blocked[strings.ToUpper(key)] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, replace := blocked[strings.ToUpper(key)]; !replace {
			environment = append(environment, entry)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}
