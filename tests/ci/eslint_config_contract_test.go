package ci

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type eslintDiagnostic struct {
	RuleID string `json:"ruleId"`
	Fatal  bool   `json:"fatal"`
}

type eslintConfigSnapshot struct {
	ECMAVersion int               `json:"ecmaVersion"`
	SourceType  string            `json:"sourceType"`
	Globals     map[string]string `json:"globals"`
}

type eslintContractResult struct {
	Configs     map[string]eslintConfigSnapshot `json:"configs"`
	Diagnostics map[string][]eslintDiagnostic   `json:"diagnostics"`
	Ignored     map[string]bool                 `json:"ignored"`
}

func TestESLintFlatConfigEffectiveBehavior(t *testing.T) {
	repoRoot := repositoryRoot(t)
	nodeBinary, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("locate Node.js required by package.json: %v", err)
	}
	configURL := canonicalFileURL(t, filepath.Join(repoRoot, "eslint.config.mjs"))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	browserScripts := browserScriptPaths(t)
	harnessArgs := append([]string{"--input-type=module", "--eval", eslintContractHarness, configURL}, browserScripts...)
	cmd := exec.CommandContext(ctx, nodeBinary, harnessArgs...) // #nosec G204 -- test invokes the explicitly resolved Node binary with a fixed inline harness, the repository-local config URL and repository-local script paths.
	cmd.Dir = repoRoot
	output, runErr := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("ESLint effective-config harness timed out after 90s")
	}
	if runErr != nil {
		t.Fatalf("ESLint effective-config harness failed: %v\n%s", runErr, output)
	}
	var result eslintContractResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode ESLint effective-config JSON: %v\n%s", err, output)
	}

	for _, path := range browserScripts {
		t.Run(path, func(t *testing.T) {
			got, ok := result.Configs[path]
			if !ok {
				t.Fatalf("ESLint effective-config harness returned no config for %s", path)
			}
			assertESLintConfig(t, got, 2022, "script", []string{"document", "Event", "localStorage", "navigator", "Number", "URL", "window"}, []string{"console", "module", "process"})
		})
	}
	assertESLintConfig(t, result.Configs["build"], 2022, "module", []string{"console", "module", "process", "URL"}, []string{"document", "Event", "localStorage", "navigator", "window"})

	for _, name := range []string{"browser-unknown", "browser-node-global", "build-unknown", "build-browser-global"} {
		assertESLintRule(t, result.Diagnostics[name], "no-undef")
	}
	for _, name := range []string{"browser-readonly", "build-readonly"} {
		assertESLintRule(t, result.Diagnostics[name], "no-global-assign")
	}
	for _, name := range []string{"browser-known", "build-known"} {
		assertNoESLintRule(t, result.Diagnostics[name], "no-undef")
	}
	for _, name := range []string{"browser-module-syntax", "build-script-syntax"} {
		if !hasFatalESLintDiagnostic(result.Diagnostics[name]) {
			t.Fatalf("%s diagnostics = %#v, want a fatal parser diagnostic", name, result.Diagnostics[name])
		}
	}
	for _, name := range []string{"build-module-syntax", "browser-script-syntax"} {
		if hasFatalESLintDiagnostic(result.Diagnostics[name]) {
			t.Fatalf("%s diagnostics = %#v, want syntax accepted by its configured parser mode", name, result.Diagnostics[name])
		}
	}

	for _, path := range []string{"internal/web/static/htmx.min.js", "internal/web/static/tailwind.css", "node_modules/example/index.js"} {
		if !result.Ignored[path] {
			t.Fatalf("ESLint effective config does not ignore %s", path)
		}
	}
}

// vendoredBrowserScripts are third-party files in internal/web/static that
// stay out of ESLint and lint:js; every other static script is first-party.
var vendoredBrowserScripts = map[string]bool{
	"htmx.min.js": true,
}

// browserScriptPaths lists every first-party internal/web/static/*.js file as
// a slash-separated repository-relative path, sorted.
func browserScriptPaths(t *testing.T) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(repositoryRoot(t), "internal", "web", "static", "*.js"))
	if err != nil {
		t.Fatalf("list internal/web/static scripts: %v", err)
	}
	var paths []string
	for _, match := range matches {
		name := filepath.Base(match)
		if vendoredBrowserScripts[name] {
			continue
		}
		paths = append(paths, "internal/web/static/"+name)
	}
	if len(paths) == 0 {
		t.Fatal("no first-party scripts found in internal/web/static")
	}
	slices.Sort(paths)
	return paths
}

func assertESLintConfig(t *testing.T, got eslintConfigSnapshot, ecmaVersion int, sourceType string, present, absent []string) {
	t.Helper()

	if got.ECMAVersion != ecmaVersion || got.SourceType != sourceType {
		t.Fatalf("ESLint language options = ecmaVersion %d sourceType %q, want %d %q", got.ECMAVersion, got.SourceType, ecmaVersion, sourceType)
	}
	for _, name := range present {
		if got.Globals[name] != "readonly" {
			t.Fatalf("ESLint global %s = %q, want readonly", name, got.Globals[name])
		}
	}
	for _, name := range absent {
		if _, exists := got.Globals[name]; exists {
			t.Fatalf("ESLint target unexpectedly exposes %s global", name)
		}
	}
}

func assertESLintRule(t *testing.T, diagnostics []eslintDiagnostic, ruleID string) {
	t.Helper()

	for _, diagnostic := range diagnostics {
		if diagnostic.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("ESLint diagnostics = %#v, want rule %s", diagnostics, ruleID)
}

func assertNoESLintRule(t *testing.T, diagnostics []eslintDiagnostic, ruleID string) {
	t.Helper()

	for _, diagnostic := range diagnostics {
		if diagnostic.RuleID == ruleID {
			t.Fatalf("ESLint diagnostics = %#v, do not want rule %s", diagnostics, ruleID)
		}
	}
}

func hasFatalESLintDiagnostic(diagnostics []eslintDiagnostic) bool {
	return slices.ContainsFunc(diagnostics, func(diagnostic eslintDiagnostic) bool {
		return diagnostic.Fatal
	})
}

const eslintContractHarness = `
import { ESLint } from "eslint";

const loaded = await import(process.argv[1]);
const eslint = new ESLint({
  cwd: process.cwd(),
  overrideConfigFile: true,
  overrideConfig: loaded.default,
});
const targets = {
  "build": "scripts/build-web-assets.mjs",
};
for (const browserScript of process.argv.slice(2)) {
  targets[browserScript] = browserScript;
}

const configs = {};
for (const [name, filePath] of Object.entries(targets)) {
  const config = await eslint.calculateConfigForFile(filePath);
  configs[name] = {
    ecmaVersion: config.languageOptions.ecmaVersion,
    sourceType: config.languageOptions.sourceType,
    globals: config.languageOptions.globals ?? {},
  };
}

async function diagnostics(filePath, code) {
  const [result] = await eslint.lintText(code, { filePath });
  return result.messages.map(({ ruleId, fatal }) => ({ ruleId, fatal: fatal === true }));
}

const browserPath = "internal/web/static/auto-refresh.js";
const buildPath = targets.build;
const checks = {
  "browser-known": await diagnostics(browserPath, "document; window;"),
  "browser-unknown": await diagnostics(browserPath, "packmonUnknown;"),
  "browser-node-global": await diagnostics(browserPath, "process;"),
  "browser-readonly": await diagnostics(browserPath, "document = null;"),
  "build-known": await diagnostics(buildPath, "process; console;"),
  "build-unknown": await diagnostics(buildPath, "packmonUnknown;"),
  "build-browser-global": await diagnostics(buildPath, "document;"),
  "build-readonly": await diagnostics(buildPath, "process = null;"),
  "browser-module-syntax": await diagnostics(browserPath, "export default 1;"),
  "build-module-syntax": await diagnostics(buildPath, "export default 1;"),
  "browser-script-syntax": await diagnostics(browserPath, "with ({ value: 1 }) { value; }"),
  "build-script-syntax": await diagnostics(buildPath, "with ({ value: 1 }) { value; }"),
};

const ignored = {};
for (const filePath of [
  "internal/web/static/htmx.min.js",
  "internal/web/static/tailwind.css",
  "node_modules/example/index.js",
]) {
  ignored[filePath] = await eslint.isPathIgnored(filePath);
}

process.stdout.write(JSON.stringify({ configs, diagnostics: checks, ignored }));
`
