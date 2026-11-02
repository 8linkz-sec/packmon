//go:build windows

package main

import (
	"path/filepath"
	"testing"
)

func TestHTMLReportRelativePathRejectsInvalidWindowsPaths(t *testing.T) {
	validRoot := t.TempDir()
	validPath := filepath.Join(validRoot, "go.sum")

	tests := []struct {
		name string
		root string
		path string
	}{
		{name: "invalid root", root: "\x00", path: validPath},
		{name: "invalid source", root: validRoot, path: "\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rel, ok := htmlReportRelativePath(tt.root, tt.path); ok || rel != "" {
				t.Fatalf("htmlReportRelativePath(%q, %q) = (%q, %t), want empty, false", tt.root, tt.path, rel, ok)
			}
		})
	}
}
