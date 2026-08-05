package domain

import "strings"

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityNone     Severity = "NONE"
)

// Valid returns true if the severity is a known value.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown, SeverityNone:
		return true
	}
	return false
}

// ParseBlockThreshold normalizes and validates the vulnerability blocking
// threshold accepted by configuration, admin settings, and API runtime policy.
func ParseBlockThreshold(raw string) (Severity, bool) {
	switch threshold := Severity(strings.ToUpper(strings.TrimSpace(raw))); threshold {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
		return threshold, true
	default:
		return "", false
	}
}

// Blocks returns true if this severity is at or above the given threshold.
func (s Severity) Blocks(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// Rank returns a numeric rank for sorting (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityUnknown:
		return 1
	default:
		return 0
	}
}
