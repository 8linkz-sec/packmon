package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/8linkz/packmon/internal/domain"
)

// JSONWriter writes scan results as JSON.
type JSONWriter struct{}

// NewJSONWriter creates a JSONWriter.
func NewJSONWriter() *JSONWriter { return &JSONWriter{} }

// Write writes the scan result as pretty-printed JSON to w.
// The output uses 2-space indentation and a trailing newline.
func (jw *JSONWriter) Write(w io.Writer, result *domain.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("json: encode: %w", err)
	}
	return nil
}

// WriteFile writes the scan result as JSON to the given file path.
func (jw *JSONWriter) WriteFile(path string, result *domain.ScanResult) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("json: create file %s: %w", path, err)
	}

	if err := jw.Write(f, result); err != nil {
		closeSilently(f)
		return err
	}
	return f.Close()
}
