package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// baseFilename returns the last element of a file path, handling both
// forward and backward slashes for cross-platform compatibility.
func baseFilename(path string) string {
	return filepath.Base(path)
}

func decodeStrictJSON(r io.Reader, v any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return withJSONSyntaxLocation(data, err)
	}

	var extra struct{}
	if err := dec.Decode(&extra); err == nil || err != io.EOF {
		if err != nil {
			return withJSONSyntaxLocation(data, err)
		}
		return fmt.Errorf("unexpected trailing data after JSON value")
	}
	return nil
}

func withJSONSyntaxLocation(data []byte, err error) error {
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		return err
	}

	line, column := jsonSyntaxLocation(data, syntaxErr.Offset)
	return fmt.Errorf("%w (line %d, column %d)", err, line, column)
}

func jsonSyntaxLocation(data []byte, offset int64) (int, int) {
	if offset < 1 {
		return 1, 1
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}

	line, column := 1, 1
	for i := int64(0); i < offset-1; i++ {
		if data[i] == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}
	return line, column
}

func cleanSourceRefs(refs ...string) []string {
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			seen[ref] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}
