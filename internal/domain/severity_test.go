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
		{Severity("INVALID"), false},
		{Severity(""), false},
	}

	for _, tt := range tests {
		if got := tt.s.Valid(); got != tt.want {
			t.Errorf("Severity(%q).Valid() = %v, want %v", tt.s, got, tt.want)
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
		{SeverityUnknown, SeverityLow, false},
	}

	for _, tt := range tests {
		if got := tt.s.Blocks(tt.threshold); got != tt.want {
			t.Errorf("Severity(%q).Blocks(%q) = %v, want %v", tt.s, tt.threshold, got, tt.want)
		}
	}
}
