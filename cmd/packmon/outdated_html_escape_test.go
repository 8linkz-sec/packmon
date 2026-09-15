package main

import (
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutdatedHTMLEscapesHostilePackageMetadata(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"target":    `target-<img src=x onerror=alert(1)>`,
		"name":      `name-<script>alert("name")</script>`,
		"installed": `installed-<svg/onload=alert(2)>`,
		"latest":    `latest-\" onmouseover=alert(3) x=\"`,
		"ecosystem": `ecosystem-<iframe src=javascript:alert(4)>`,
		"scope":     `scope-<details open ontoggle=alert(5)>`,
		"relation":  `relation-<math href=javascript:alert(6)>`,
		"via":       `via-<video onerror=alert(7)>`,
		"flags":     `flags-<object data=javascript:alert(8)>`,
		"lockfile":  `lockfile-<a href=javascript:alert(9)>`,
	}
	report := outdatedReport{
		Target:      values["target"],
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      values["name"],
			Installed: values["installed"],
			Latest:    values["latest"],
			Ecosystem: values["ecosystem"],
			Scope:     values["scope"],
			Relation:  values["relation"],
			Via:       values["via"],
			Flags:     values["flags"],
			LockFile:  values["lockfile"],
		}},
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	out := string(data)

	for field, value := range values {
		if strings.Contains(out, value) {
			t.Fatalf("outdated HTML rendered raw hostile %s value %q:\n%s", field, value, out)
		}
		if want := html.EscapeString(value); !strings.Contains(out, want) {
			t.Fatalf("outdated HTML missing escaped %s value %q:\n%s", field, want, out)
		}
	}
	for _, forbiddenElement := range []string{"<img", "<svg", "<iframe", "<details open", "<math", "<video", "<object", "<a href=javascript"} {
		if strings.Contains(out, forbiddenElement) {
			t.Fatalf("outdated HTML rendered hostile element %q:\n%s", forbiddenElement, out)
		}
	}
}
