package parser

import (
	"encoding/json"
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
	dec := json.NewDecoder(r)
	if err := dec.Decode(v); err != nil {
		return err
	}

	var extra struct{}
	if err := dec.Decode(&extra); err == nil || err != io.EOF {
		return fmt.Errorf("unexpected trailing data after JSON value")
	}
	return nil
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
