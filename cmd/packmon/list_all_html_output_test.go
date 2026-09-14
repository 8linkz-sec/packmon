package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestWriteListAllHTMLDefaultsBlankTitleAndWrapsPrivateFileOpenError(t *testing.T) {
	t.Parallel()

	t.Run("blank title", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "report.html")
		if err := writeListAllHTML(path, " \t ", &domain.ScanResult{}, listAllPackageReport{}); err != nil {
			t.Fatalf("writeListAllHTML: %v", err)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- test reads its generated report.
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		if !strings.Contains(string(data), "<title>Packmon List-All Report</title>") {
			t.Fatalf("blank title report does not use the default title:\n%s", data)
		}
	})

	t.Run("existing directory is not an output file", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir()
		err := writeListAllHTML(path, "report", &domain.ScanResult{}, listAllPackageReport{})
		if err == nil {
			t.Fatal("writeListAllHTML(existing directory) succeeded")
		}
		if !strings.Contains(err.Error(), "html: create file "+path) {
			t.Fatalf("writeListAllHTML(existing directory) = %v, want private-file context", err)
		}
	})
}
