package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminAdvisoryActionsUseSharedPartial(t *testing.T) {
	source := readAdminAdvisoryTemplateFile(t)

	partial := extractTemplateDefinition(t, source, "admin-advisory-actions")
	for _, want := range []string{
		`href="/admin/advisories?edit={{.Advisory.ID}}{{if gt .CurrentOffset 0}}&amp;offset={{.CurrentOffset}}{{end}}"`,
		`action="/admin/advisories/delete"`,
		`name="_csrf" value="{{.CSRFToken}}"`,
		`name="return_offset" value="{{.CurrentOffset}}"`,
		`data-submit-lock-label="{{t "admin.advisories.action.deleting"}}"`,
		`id="adv-delete-confirm-{{.ConfirmIDPrefix}}-{{.Advisory.ID}}"`,
		`aria-label="{{t "admin.advisories.action.confirm_delete_aria" .Advisory.ID .Advisory.Ecosystem .Advisory.Name}}"`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("admin-advisory-actions partial missing %q:\n%s", want, partial)
		}
	}

	mobile := extractMarkedSection(t, source, `data-admin-mobile-actions="advisories"`)
	desktop := extractMarkedSection(t, source, `data-admin-desktop-table="advisories"`)
	for name, section := range map[string]string{
		"mobile":  mobile,
		"desktop": desktop,
	} {
		if got := strings.Count(section, `{{template "admin-advisory-actions"`); got != 1 {
			t.Fatalf("%s advisory section admin-advisory-actions calls = %d, want 1:\n%s", name, got, section)
		}
		for _, duplicated := range []string{
			`href="/admin/advisories?edit=`,
			`action="/admin/advisories/delete"`,
			`admin.advisories.action.deleting`,
			`admin.advisories.action.confirm_delete_aria`,
		} {
			if strings.Contains(section, duplicated) {
				t.Fatalf("%s advisory section still copies shared action markup %q:\n%s", name, duplicated, section)
			}
		}
	}
}

func readAdminAdvisoryTemplateFile(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("templates", "admin", "advisories.html"))
	if err != nil {
		t.Fatalf("read admin advisories template: %v", err)
	}
	return string(data)
}

func extractTemplateDefinition(t *testing.T, source, name string) string {
	t.Helper()

	marker := `{{define "` + name + `"}}`
	index := strings.Index(source, marker)
	if index < 0 {
		t.Fatalf("template definition %q missing:\n%s", name, source)
	}
	partial := source[index+len(marker):]
	if !strings.Contains(partial, "{{end}}") {
		t.Fatalf("template definition %q missing closing end:\n%s", name, partial)
	}
	return partial
}

func extractMarkedSection(t *testing.T, source, marker string) string {
	t.Helper()

	index := strings.Index(source, marker)
	if index < 0 {
		t.Fatalf("template section marker %q missing:\n%s", marker, source)
	}
	start := strings.LastIndex(source[:index], "<div")
	if start < 0 {
		t.Fatalf("template section marker %q has no containing div:\n%s", marker, source)
	}
	sectionEnd := len(source)
	for _, endMarker := range []string{
		`data-admin-desktop-table="advisories"`,
		`{{else if .AdvisoryPageOutOfRange}}`,
		`{{define "admin-advisory-actions"}}`,
	} {
		if endMarker == marker {
			continue
		}
		if next := strings.Index(source[index+len(marker):], endMarker); next >= 0 {
			end := index + len(marker) + next
			if end < sectionEnd {
				sectionEnd = end
			}
		}
	}
	return source[start:sectionEnd]
}
