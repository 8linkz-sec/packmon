package scanner

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestTableWriterColorSeverity(t *testing.T) {
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
}

func TestTableWriterUsesDomainBlockingSeverityParser(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("table.go") // #nosec G304 -- test inspects fixed package source file.
	if err != nil {
		t.Fatalf("read table.go: %v", err)
	}
	text := string(data)
	for _, forbidden := range []string{
		"func SeverityFromString(",
		`case "CRITICAL":`,
		`case "HIGH":`,
		`case "MEDIUM":`,
		`case "LOW":`,
		`case "NONE":`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("table.go still owns blocking severity parsing via %q", forbidden)
		}
	}
	if !strings.Contains(text, "domain.ParseBlockThreshold(") {
		t.Fatal("table.go does not use the domain blocking severity parser")
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
