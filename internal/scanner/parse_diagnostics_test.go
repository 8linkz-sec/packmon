package scanner

import (
	"fmt"
	"reflect"
	"testing"
)

func TestBoundedParseDiagnosticsTrimsBlanksBeforeApplyingLimit(t *testing.T) {
	parseErrors := []string{"\tfirst\n", " ", "second"}
	for index := 3; index <= MaxUserFacingParseDiagnostics; index++ {
		parseErrors = append(parseErrors, fmt.Sprintf("diagnostic %d", index))
	}
	parseErrors = append(parseErrors, "\t", "  overflow diagnostic  ")

	visible, omitted := BoundedParseDiagnostics(parseErrors)
	wantVisible := make([]string, 0, MaxUserFacingParseDiagnostics)
	wantVisible = append(wantVisible, "first", "second")
	for index := 3; index <= MaxUserFacingParseDiagnostics; index++ {
		wantVisible = append(wantVisible, fmt.Sprintf("diagnostic %d", index))
	}

	if !reflect.DeepEqual(visible, wantVisible) {
		t.Fatalf("visible diagnostics = %#v, want %#v", visible, wantVisible)
	}
	if omitted != 1 {
		t.Fatalf("omitted diagnostics = %d, want 1", omitted)
	}
}

func TestBoundedParseDiagnosticsIgnoresOnlyBlankDiagnostics(t *testing.T) {
	visible, omitted := BoundedParseDiagnostics([]string{"", " \t\n "})
	if len(visible) != 0 {
		t.Fatalf("visible diagnostics = %#v, want none", visible)
	}
	if omitted != 0 {
		t.Fatalf("omitted diagnostics = %d, want 0", omitted)
	}
}

func TestParseDiagnosticsOmittedSummaryReportsCountAndJSONHint(t *testing.T) {
	if got, want := ParseDiagnosticsOmittedSummary(3), "3 additional parse diagnostics omitted; see JSON parse_errors for full detail"; got != want {
		t.Fatalf("omitted summary = %q, want %q", got, want)
	}
	for _, omitted := range []int{0, -1} {
		if got := ParseDiagnosticsOmittedSummary(omitted); got != "" {
			t.Fatalf("summary for omitted=%d = %q, want empty", omitted, got)
		}
	}
}
