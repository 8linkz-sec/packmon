package ci

import (
	"os"
	"strings"
	"testing"
)

func TestServerScanLogStorageOmitsDisallowedClientMetadata(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		path      string
		extractor func(string) string
	}{
		{
			name: "model",
			path: "../../internal/db/db.go",
			extractor: func(text string) string {
				return textBlockBetween(t, text, "type ScanLogEntry struct {", "\n}")
			},
		},
		{
			name: "postgres queries",
			path: "../../internal/db/postgres/scan_logs.go",
			extractor: func(text string) string {
				return text
			},
		},
		{
			name: "initial schema",
			path: "../../internal/db/postgres/migrations/001_initial.up.sql",
			extractor: func(text string) string {
				return textBlockBetween(t, text, "CREATE TABLE scan_log (", "\n);")
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("read %s: %v", tt.path, err)
			}
			target := strings.ToLower(tt.extractor(string(raw)))
			for _, forbidden := range []string{"branch", "commit", "user_agent"} {
				if strings.Contains(target, forbidden) {
					t.Fatalf("%s contains disallowed server scan-log metadata %q", tt.path, forbidden)
				}
			}
		})
	}
}

func textBlockBetween(t *testing.T, text, start, end string) string {
	t.Helper()
	startIndex := strings.Index(text, start)
	if startIndex < 0 {
		t.Fatalf("missing block start %q", start)
	}
	text = text[startIndex+len(start):]
	endIndex := strings.Index(text, end)
	if endIndex < 0 {
		t.Fatalf("missing block end %q", end)
	}
	return text[:endIndex]
}
