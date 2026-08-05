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
	if looksAbsolutePath(path) {
		return safeHTMLExternalPath(path)
	}
	display := cleanHTMLRelativePath(path)
	if display == "." {
		// `packmon scan .` would only restate that the scan ran in the current
		// directory. The report heading already names that directory, so the
		// meta line drops the entry (and its separator) instead.
		return ""
	}
	return display
}

func htmlReportDisplaySourcePath(root, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !looksAbsolutePath(path) {
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
	base := reportPathLastSegment(path)
	if strings.TrimSpace(base) == "" || base == "." || base == ".." ||
		base == string(filepath.Separator) || strings.HasSuffix(base, ":") {
		return "external-file"
	}
	return base
}

// looksAbsolutePath reports whether path is absolute under either the POSIX or
// the Windows convention, not merely the host platform's own.
//
// filepath.IsAbs only knows the local convention, so a POSIX path handed to a
// Windows build -- or a drive path handed to a Linux build -- was classified as
// relative and rendered into the report in full. That defeats the purpose of
// this file, which exists to keep filesystem layout out of the report.
func looksAbsolutePath(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\\`) {
		return true
	}
	// Drive-letter form, with either separator: C:\... or C:/...
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		drive := path[0]
		return (drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')
	}
	return false
}

// reportPathLastSegment returns the final segment of path, treating both `/`
// and `\` as separators so the reduction is identical on every platform.
func reportPathLastSegment(path string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(path), `/\`)
	if index := strings.LastIndexAny(trimmed, `/\`); index >= 0 {
		return trimmed[index+1:]
	}
	return trimmed
}
