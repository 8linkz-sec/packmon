package main

import (
	"errors"
	"strconv"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

var errListAllTerminalWrite = errors.New("list-all terminal write failed")

type failListAllTerminalWriter struct {
	failAt int
	writes int
}

func (w *failListAllTerminalWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errListAllTerminalWrite
	}
	return len(p), nil
}

func TestWriteListAllSecurityFindingsPropagatesWriterErrors(t *testing.T) {
	tests := []struct {
		name   string
		result *domain.ScanResult
		failAt int
	}{
		{name: "incomplete result message", result: nil, failAt: 2},
		{name: "empty result table", result: &domain.ScanResult{}, failAt: 1},
		{name: "status message", result: listAllWriterFindingResult(), failAt: 2},
		{name: "section heading", result: listAllWriterFindingResult(), failAt: 3},
		{name: "table header", result: listAllWriterFindingResult(), failAt: 4},
		{name: "row prefix", result: listAllWriterFindingResult(), failAt: 5},
		{name: "row body", result: listAllWriterFindingResult(), failAt: 6},
		{name: "details", result: listAllWriterFindingResult(), failAt: 7},
		{name: "summary", result: listAllWriterFindingResult(), failAt: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &failListAllTerminalWriter{failAt: tt.failAt}
			err := writeListAllSecurityFindings(writer, tt.result, domain.SeverityHigh, listAllPackageReport{}, true)
			if !errors.Is(err, errListAllTerminalWrite) {
				t.Fatalf("writeListAllSecurityFindings() error = %v, want sentinel", err)
			}
			if writer.writes != tt.failAt {
				t.Fatalf("writer calls = %d, want failure at %d", writer.writes, tt.failAt)
			}
		})
	}
}

func TestListAllTerminalFindingTableAndRowPropagateWriterErrors(t *testing.T) {
	row := listAllWriterFindingRow()
	for _, failAt := range []int{1, 2, 3, 4} {
		t.Run("table write "+strconv.Itoa(failAt), func(t *testing.T) {
			writer := &failListAllTerminalWriter{failAt: failAt}
			err := writeListAllTerminalFindingTable(writer, []listAllFindingRow{row}, true)
			if !errors.Is(err, errListAllTerminalWrite) {
				t.Fatalf("writeListAllTerminalFindingTable() error = %v, want sentinel", err)
			}
		})
	}
	for _, failAt := range []int{1, 2} {
		t.Run("row write "+strconv.Itoa(failAt), func(t *testing.T) {
			writer := &failListAllTerminalWriter{failAt: failAt}
			err := writeListAllTerminalFindingRow(writer, row, "%-8s  %s\n", 8, true)
			if !errors.Is(err, errListAllTerminalWrite) {
				t.Fatalf("writeListAllTerminalFindingRow() error = %v, want sentinel", err)
			}
		})
	}
}

func TestSortListAllFindingRowsOrdersSeverityThenPackage(t *testing.T) {
	rows := []listAllFindingRow{
		{Severity: string(domain.SeverityLow), Package: "z-low"},
		{Severity: string(domain.SeverityHigh), Package: "z-high"},
		{Severity: string(domain.SeverityCritical), Package: "critical"},
		{Severity: string(domain.SeverityMedium), Package: "medium"},
		{Severity: string(domain.SeverityHigh), Package: "a-high"},
	}
	sortListAllFindingRows(rows)
	want := []string{"critical", "a-high", "z-high", "medium", "z-low"}
	for i, name := range want {
		if rows[i].Package != name {
			t.Fatalf("sorted row %d package = %q, want %q; rows=%+v", i, rows[i].Package, name, rows)
		}
	}
}

func listAllWriterFindingResult() *domain.ScanResult {
	return &domain.ScanResult{
		FindingsCount:    1,
		FindingsBlocking: true,
		PackagesScanned:  1,
		ScanError:        "fixture scan warning",
		Findings: []domain.Finding{{
			Name:       "fixture-package",
			Version:    "1.0.0",
			Ecosystem:  domain.Ecosystem("npm"),
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-fixture",
			Title:      "fixture finding",
			Source:     "fixture",
		}},
	}
}

func listAllWriterFindingRow() listAllFindingRow {
	return listAllFindingRow{
		Severity: string(domain.SeverityHigh),
		Package:  "fixture-package",
		Advisory: "GHSA-fixture",
		Title:    "fixture finding",
		Action:   "update",
	}
}
