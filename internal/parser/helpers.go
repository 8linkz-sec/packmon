package parser

import "path/filepath"

// baseFilename returns the last element of a file path, handling both
// forward and backward slashes for cross-platform compatibility.
func baseFilename(path string) string {
	return filepath.Base(path)
}
