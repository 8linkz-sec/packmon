package main

import "time"

func formatReportTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
