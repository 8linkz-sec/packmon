package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailwindV4AssetsAreConfiguredAndGenerated(t *testing.T) {
	t.Parallel()

	packageJSON := readTextFile(t, "..", "..", "package.json")
	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(packageJSON), &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	if got := pkg.DevDependencies["tailwindcss"]; !strings.HasPrefix(got, "4.") {
		t.Fatalf("tailwindcss dependency = %q, want v4", got)
	}
	if got := pkg.DevDependencies["@tailwindcss/cli"]; !strings.HasPrefix(got, "4.") {
		t.Fatalf("@tailwindcss/cli dependency = %q, want v4", got)
	}
	if got := pkg.Scripts["build:web:css"]; !strings.Contains(got, "@tailwindcss/cli") {
		t.Fatalf("build:web:css = %q, want @tailwindcss/cli", got)
	}

	inputCSS := readTextFile(t, "static", "tailwind.input.css")
	for _, want := range []string{
		`@import "tailwindcss" source(none);`,
		`@config "../../../tailwind.config.js";`,
		`@source "../templates";`,
		`@source "../*.go";`,
	} {
		if !strings.Contains(inputCSS, want) {
			t.Fatalf("tailwind.input.css missing %q:\n%s", want, inputCSS)
		}
	}

	outputCSS := readTextFile(t, "static", "tailwind.css")
	for _, want := range []string{
		".rounded{",
		".shadow{",
		".space-y-4>",
		".space-x-4>",
		".border-gray-200{",
		".bg-blue-600{",
		".hover\\:bg-blue-700:hover",
		".focus\\:ring-blue-500:focus",
	} {
		if !strings.Contains(outputCSS, want) {
			t.Fatalf("tailwind.css missing generated selector %q", want)
		}
	}
}

func readTextFile(t *testing.T, path ...string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(path...), err)
	}
	return string(content)
}
