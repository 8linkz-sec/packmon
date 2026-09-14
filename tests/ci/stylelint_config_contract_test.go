package ci

import (
	"encoding/json"
	"reflect"
	"testing"
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
		"block-no-empty":                           true,
		"color-no-invalid-hex":                      true,
		"declaration-block-no-duplicate-properties": true,
		"function-calc-no-unspaced-operator":        true,
		"no-duplicate-selectors":                     true,
		"no-invalid-double-slash-comments":           true,
		"selector-type-no-unknown":                   true,
	}
	if !reflect.DeepEqual(config.Rules, wantRules) {
		t.Fatalf(".stylelintrc.json rules = %#v, want %#v", config.Rules, wantRules)
	}
}
