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
	cmd := exec.CommandContext(ctx, nodeBinary, "--input-type=module", "--eval", eslintContractHarness, configURL) // #nosec G204 -- test invokes the explicitly resolved Node binary with a fixed inline harness and repository-local config URL.
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

	for _, target := range []string{"auto-refresh", "theme-init"} {
		assertESLintConfig(t, result.Configs[target], 2022, "script", []string{"document", "Event", "localStorage", "navigator", "Number", "window"}, []string{"module", "process", "URL"})
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
  "auto-refresh": "internal/web/static/auto-refresh.js",
  "theme-init": "internal/web/static/theme-init.js",
  "build": "scripts/build-web-assets.mjs",
};

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

const browserPath = targets["auto-refresh"];
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
