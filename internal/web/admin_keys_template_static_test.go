package web

import (
	"strings"
	"testing"
)

func TestAdminAPIKeyRowActionsUseSharedTemplatePartials(t *testing.T) {
	t.Parallel()

	keys := readTemplateFile(t, "admin", "keys.html")

	for _, want := range []string{
		`{{define "admin-key-status-badge"}}`,
		`{{define "admin-key-actions"}}`,
		`action="/admin/keys/revoke"`,
		`action="/admin/keys/delete"`,
		`name="_csrf" value="{{.Root.CSRFToken}}"`,
		`name="return_offset" value="{{.Root.KeyCurrentOffset}}"`,
		`data-submit-lock-label="{{t "admin.keys.action.revoking"}}"`,
		`data-submit-lock-label="{{t "admin.keys.action.deleting"}}"`,
		`aria-label="{{t "admin.keys.action.confirm_revoke_aria" .Key.Name .Key.ID}}"`,
		`aria-label="{{t "admin.keys.action.confirm_delete_aria" .Key.Name .Key.ID}}"`,
	} {
		if !strings.Contains(keys, want) {
			t.Fatalf("admin keys template missing shared API key partial fragment %q:\n%s", want, keys)
		}
	}

	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
	}{
		{
			name:        "mobile",
			startMarker: `data-admin-mobile-actions="keys"`,
			endMarker:   `data-admin-desktop-table="keys"`,
		},
		{
			name:        "desktop",
			startMarker: `data-admin-desktop-table="keys"`,
			endMarker:   `No API keys created yet.`,
		},
	} {
		section := templateSectionBetween(t, keys, tc.startMarker, tc.endMarker)
		if got := strings.Count(section, `{{template "admin-key-status-badge"`); got != 1 {
			t.Fatalf("%s admin keys layout status partial calls = %d, want 1:\n%s", tc.name, got, section)
		}
		if got := strings.Count(section, `{{template "admin-key-actions"`); got != 1 {
			t.Fatalf("%s admin keys layout actions partial calls = %d, want 1:\n%s", tc.name, got, section)
		}
		for _, blocked := range []string{
			`action="/admin/keys/revoke"`,
			`action="/admin/keys/delete"`,
			`admin.keys.action.confirm_revoke`,
			`admin.keys.action.confirm_delete`,
		} {
			if strings.Contains(section, blocked) {
				t.Fatalf("%s admin keys layout still contains direct action markup %q:\n%s", tc.name, blocked, section)
			}
		}
	}
}

func templateSectionBetween(t *testing.T, body, startMarker, endMarker string) string {
	t.Helper()

	start := strings.Index(body, startMarker)
	if start == -1 {
		t.Fatalf("template missing start marker %q", startMarker)
	}
	end := strings.Index(body[start:], endMarker)
	if end == -1 {
		t.Fatalf("template missing end marker %q after %q", endMarker, startMarker)
	}
	return body[start : start+end]
}
