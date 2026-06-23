package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestTableWriterColorSeverityAndSeverityParsing(t *testing.T) {
	t.Parallel()

	noColor := NewTableWriter(true)
	if got := noColor.colorSeverity(domain.SeverityCritical); got != "CRITICAL" {
		t.Fatalf("no-color critical = %q", got)
	}

	colored := NewTableWriter(false)
	for _, sev := range []domain.Severity{
		domain.SeverityCritical,
		domain.SeverityHigh,
		domain.SeverityMedium,
		domain.SeverityLow,
		domain.SeverityUnknown,
	} {
		if got := colored.colorSeverity(sev); !strings.Contains(got, string(sev)) || !strings.Contains(got, colorReset) {
			t.Fatalf("colorSeverity(%q) = %q, want colored severity", sev, got)
		}
	}

	for _, tt := range []struct {
		raw  string
		want domain.Severity
	}{
		{" critical ", domain.SeverityCritical},
		{"high", domain.SeverityHigh},
		{"medium", domain.SeverityMedium},
		{"low", domain.SeverityLow},
		{"none", domain.SeverityNone},
	} {
		got, ok := SeverityFromString(tt.raw)
		if !ok || got != tt.want {
			t.Fatalf("SeverityFromString(%q) = %q, %v; want %q true", tt.raw, got, ok, tt.want)
		}
	}
	if got, ok := SeverityFromString("unknown"); ok || got != "" {
		t.Fatalf("SeverityFromString(unknown) = %q, %v; want empty false", got, ok)
	}
}

func TestScannerTruncate(t *testing.T) {
	t.Parallel()

	if got := truncate("short", 10); got != "short" {
		t.Fatalf("truncate(short) = %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Fatalf("truncate(long) = %q", got)
	}
	if got := truncate("ääääää", 3); got != "äää..." || !utf8.ValidString(got) {
		t.Fatalf("truncate(utf8) = %q, valid=%v; want %q", got, utf8.ValidString(got), "äää...")
	}
}
