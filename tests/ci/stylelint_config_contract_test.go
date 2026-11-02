package ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStylelintConfigUsesExpectedStructuredRules(t *testing.T) {
	t.Parallel()

	var config struct {
		IgnoreFiles []string        `json:"ignoreFiles"`
		Rules       map[string]bool `json:"rules"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, ".stylelintrc.json")), &config); err != nil {
		t.Fatalf("parse .stylelintrc.json: %v", err)
	}

	wantIgnoredFiles := []string{
		"internal/web/static/htmx.min.js",
		"internal/web/static/tailwind.css",
	}
	if !reflect.DeepEqual(config.IgnoreFiles, wantIgnoredFiles) {
		t.Fatalf(".stylelintrc.json ignoreFiles = %#v, want %#v", config.IgnoreFiles, wantIgnoredFiles)
	}

	wantRules := map[string]bool{
		"block-no-empty":                            true,
		"color-no-invalid-hex":                      true,
		"declaration-block-no-duplicate-properties": true,
		"function-calc-no-unspaced-operator":        true,
		"no-duplicate-selectors":                    true,
		"no-invalid-double-slash-comments":          true,
		"selector-type-no-unknown":                  true,
	}
	if !reflect.DeepEqual(config.Rules, wantRules) {
		t.Fatalf(".stylelintrc.json rules = %#v, want %#v", config.Rules, wantRules)
	}
}

func TestStylelintConfigBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required for the Stylelint behavior contract: %v", err)
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	stylelint := filepath.Join(repoRoot, "node_modules", "stylelint", "bin", "stylelint.mjs")
	if info, statErr := os.Stat(stylelint); statErr != nil || info.IsDir() {
		t.Fatalf("repository-local Stylelint binary is required at %s: %v", stylelint, statErr)
	}

	invalidFixtures := []struct {
		name string
		css  string
		rule string
	}{
		{"block no empty", "a {}\n", "block-no-empty"},
		{"invalid hex", "a { color: #ggg; }\n", "color-no-invalid-hex"},
		{"duplicate property", "a { color: red; color: blue; }\n", "declaration-block-no-duplicate-properties"},
		{"unspaced calc operator", "a { width: calc(100%-1px); }\n", "function-calc-no-unspaced-operator"},
		{"duplicate selector", "a { color: red; }\na { color: blue; }\n", "no-duplicate-selectors"},
		{"double slash comment", "// invalid\na { color: red; }\n", "no-invalid-double-slash-comments"},
		{"unknown type selector", "packmon-unknown-element { color: red; }\n", "selector-type-no-unknown"},
	}
	for _, fixture := range invalidFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			fixtureRoot := newStylelintFixture(t)
			cssPath := filepath.Join(fixtureRoot, "invalid.css")
			if err := os.WriteFile(cssPath, []byte(fixture.css), 0o600); err != nil {
				t.Fatalf("write invalid CSS fixture: %v", err)
			}
			output, runErr := runStylelint(t, node, stylelint, fixtureRoot, cssPath)
			if runErr == nil {
				t.Fatalf("Stylelint accepted CSS invalid for %s\n%s", fixture.rule, output)
			}
			if !strings.Contains(output, fixture.rule) {
				t.Fatalf("Stylelint output missing rule %q: %v\n%s", fixture.rule, runErr, output)
			}
		})
	}

	t.Run("valid Tailwind v4 directives", func(t *testing.T) {
		fixtureRoot := newStylelintFixture(t)
		cssPath := filepath.Join(fixtureRoot, "tailwind.input.css")
		css := `@import "tailwindcss";
@source "../../templates";
@theme {
  --color-packmon: #123456;
}
@utility content-auto {
  content-visibility: auto;
}
`
		if err := os.WriteFile(cssPath, []byte(css), 0o600); err != nil {
			t.Fatalf("write valid Tailwind CSS fixture: %v", err)
		}
		output, runErr := runStylelint(t, node, stylelint, fixtureRoot, cssPath)
		if runErr != nil {
			t.Fatalf("Stylelint rejected representative Tailwind v4 CSS: %v\n%s", runErr, output)
		}
	})

	t.Run("exact generated paths are ignored", func(t *testing.T) {
		fixtureRoot := newStylelintFixture(t)
		staticDir := filepath.Join(fixtureRoot, "internal", "web", "static")
		if err := os.MkdirAll(staticDir, 0o700); err != nil {
			t.Fatalf("create generated-path fixture: %v", err)
		}
		ignored := []string{
			filepath.Join(staticDir, "htmx.min.js"),
			filepath.Join(staticDir, "tailwind.css"),
		}
		for _, path := range ignored {
			if err := os.WriteFile(path, []byte("a {}\n"), 0o600); err != nil {
				t.Fatalf("write ignored fixture %s: %v", path, err)
			}
		}
		output, runErr := runStylelint(t, node, stylelint, fixtureRoot, ignored...)
		if runErr != nil {
			t.Fatalf("Stylelint did not ignore exact generated paths: %v\n%s", runErr, output)
		}

		nearby := filepath.Join(staticDir, "tailwind.input.css")
		if err := os.WriteFile(nearby, []byte("a {}\n"), 0o600); err != nil {
			t.Fatalf("write nearby non-generated fixture: %v", err)
		}
		output, runErr = runStylelint(t, node, stylelint, fixtureRoot, nearby)
		if runErr == nil || !strings.Contains(output, "block-no-empty") {
			t.Fatalf("Stylelint ignore paths overmatched nearby source CSS: %v\n%s", runErr, output)
		}
	})
}

func newStylelintFixture(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".stylelintrc.json"), []byte(readRepoFile(t, ".stylelintrc.json")), 0o600); err != nil {
		t.Fatalf("write Stylelint config fixture: %v", err)
	}
	return root
}

func runStylelint(t *testing.T, node, stylelint, fixtureRoot string, paths ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{stylelint, "--config", filepath.Join(fixtureRoot, ".stylelintrc.json")}
	args = append(args, paths...)
	cmd := exec.CommandContext(ctx, node, args...) // #nosec G204 -- test executes resolved Node with the repository-local Stylelint entry point and temp fixtures.
	cmd.Dir = fixtureRoot
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(output), fmt.Errorf("Stylelint timed out after 30s")
	}
	return string(output), err
}
