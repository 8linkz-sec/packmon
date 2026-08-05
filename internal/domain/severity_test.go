package domain

import "testing"

func TestSeverityValid(t *testing.T) {
	tests := []struct {
		s    Severity
		want bool
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, true},
		{SeverityUnknown, true},
		{SeverityNone, true},
		{Severity("INVALID"), false},
		{Severity(""), false},
	}

	for _, tt := range tests {
		if got := tt.s.Valid(); got != tt.want {
			t.Errorf("Severity(%q).Valid() = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestParseBlockThreshold(t *testing.T) {
	tests := []struct {
		raw  string
		want Severity
		ok   bool
	}{
		{"critical", SeverityCritical, true},
		{" HIGH ", SeverityHigh, true},
		{"MEDIUM", SeverityMedium, true},
		{"low", SeverityLow, true},
		{" none ", SeverityNone, true},
		{"UNKNOWN", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got, ok := ParseBlockThreshold(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("ParseBlockThreshold(%q) = %q/%v, want %q/%v", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSeverityBlocks(t *testing.T) {
	tests := []struct {
		s         Severity
		threshold Severity
		want      bool
	}{
		{SeverityCritical, SeverityCritical, true},
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityLow, true},
		{SeverityUnknown, SeverityLow, true},
		{SeverityUnknown, SeverityMedium, false},
	}

	for _, tt := range tests {
		if got := tt.s.Blocks(tt.threshold); got != tt.want {
			t.Errorf("Severity(%q).Blocks(%q) = %v, want %v", tt.s, tt.threshold, got, tt.want)
		}
	}
}
