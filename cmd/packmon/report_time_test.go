package main

import (
	"testing"
	"time"
)

func TestFormatReportTimestamps(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, time.September, 14, 10, 30, 45, 0, time.FixedZone("CEST", 2*60*60))
	if got, want := formatReportTimestamp(instant), "2026-09-14 08:30 UTC"; got != want {
		t.Fatalf("formatReportTimestamp() = %q, want %q", got, want)
	}
	if got, want := formatReportTimestampDateTime(instant), "2026-09-14T08:30:45Z"; got != want {
		t.Fatalf("formatReportTimestampDateTime() = %q, want %q", got, want)
	}
	if got := formatReportTimestamp(time.Time{}); got != "" {
		t.Fatalf("formatReportTimestamp(zero) = %q, want empty", got)
	}
	if got := formatReportTimestampDateTime(time.Time{}); got != "" {
		t.Fatalf("formatReportTimestampDateTime(zero) = %q, want empty", got)
	}
}

func TestReportTimestampDateTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		display  string
		dateTime string
		want     string
	}{
		{
			name:     "explicit datetime takes precedence and is trimmed",
			display:  "2026-09-14 08:30 UTC",
			dateTime: "  custom-value  ",
			want:     "custom-value",
		},
		{
			name:    "UTC display timestamp",
			display: "2026-09-14 08:30 UTC",
			want:    "2026-09-14T08:30:00Z",
		},
		{
			name:    "whitespace padded UTC display timestamp",
			display: "  2026-09-14 08:30 UTC  ",
			want:    "2026-09-14T08:30:00Z",
		},
		{
			name:    "RFC3339 display normalizes to UTC",
			display: "2026-09-14T10:30:00+02:00",
			want:    "2026-09-14T08:30:00Z",
		},
		{
			name:    "missing display",
			display: "  ",
			want:    "",
		},
		{
			name:    "invalid display",
			display: "not a timestamp",
			want:    "",
		},
		{
			name:    "malformed UTC display timestamp",
			display: "2026-99-14 08:30 UTC",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportTimestampDateTime(tt.display, tt.dateTime); got != tt.want {
				t.Fatalf("reportTimestampDateTime(%q, %q) = %q, want %q", tt.display, tt.dateTime, got, tt.want)
			}
		})
	}
}
