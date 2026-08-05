package db

import (
	"fmt"
	"strings"
)

const SearchVulnerabilityIDPreviewLimit = 5

func FormatSearchVulnerabilityIDPreview(ids string, total int) string {
	parts := splitSearchVulnerabilityIDs(ids)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > SearchVulnerabilityIDPreviewLimit {
		parts = parts[:SearchVulnerabilityIDPreviewLimit]
	}
	if total > len(parts) {
		parts = append(parts, fmt.Sprintf("+%d more", total-len(parts)))
	}
	return strings.Join(parts, ", ")
}

func splitSearchVulnerabilityIDs(ids string) []string {
	raw := strings.Split(ids, ",")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
