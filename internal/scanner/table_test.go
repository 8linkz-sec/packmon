package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestTableWriterWriteShowsLocalStaleWarning(t *testing.T) {
	days := 34
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		FindingsCount:   0,
		DBAgeDays:       &days,
		DBStale:         true,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, expected := range []string{
		"Local database last synced 34 days ago",
		"Update with: packmon db sync",
		"No findings in 1 packages.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
}

func TestTableWriterWriteShowsDegradedFeedWarning(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "remote",
		FeedStatus:      "degraded",
		PackagesScanned: 2,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if !strings.Contains(out.String(), "Server reports degraded feed status") {
		t.Fatalf("expected degraded warning in table output\n%s", out.String())
	}
}
