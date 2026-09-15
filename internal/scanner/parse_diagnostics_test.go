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
