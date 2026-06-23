package main

import (
	"path/filepath"
	"strings"
)

func htmlReportDisplayTarget(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return safeHTMLExternalPath(path)
	}
	return cleanHTMLRelativePath(path)
}

func htmlReportDisplaySourcePath(root, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		return cleanHTMLRelativePath(path)
	}
	if rel, ok := htmlReportRelativePath(root, path); ok {
		return filepath.ToSlash(rel)
	}
	return safeHTMLExternalPath(path)
}

func htmlReportRelativePath(root, path string) (string, bool) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func cleanHTMLRelativePath(path string) string {
	clean := filepath.Clean(path)
	if clean == "." {
		return "."
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return safeHTMLExternalPath(clean)
	}
	return filepath.ToSlash(clean)
}

func safeHTMLExternalPath(path string) string {
	base := filepath.Base(filepath.Clean(path))
	if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
		return "external-file"
	}
	return base
}
