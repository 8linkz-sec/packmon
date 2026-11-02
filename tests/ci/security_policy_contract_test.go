package ci

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	apiAuthProtectionDecision         = "api-auth-protection"
	forwardedHeadersDecision          = "untrusted-forwarded-headers"
	metricsLoopbackDecision           = "metrics-loopback-only"
	logFileContentsDecision           = "log-file-contents"
	separateStartupMigrationsDecision = "startup-migrations"
)

var securityPolicyHeadings = []string{
	"Public and Protected Endpoints",
	"Reverse Proxy and Client IP Handling",
	"Logging and Privacy",
	"Metrics Exposure",
	"Database and Migrations",
	"Security Audit Checklist",
}

type policyBlock struct {
	listLabel string
	text      string
}

type policySection struct {
	blocks []policyBlock
}

func TestSecurityPolicyOperationalDecisionsAreConsistent(t *testing.T) {
	t.Parallel()

	policy := readSecurityPolicy(t)
	violations, err := validateSecurityPolicyDecisions(policy)
	if err != nil {
		t.Fatalf("parse SECURITY.md: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("SECURITY.md has contradictory or incomplete operational decisions: %s", strings.Join(violations, ", "))
	}
}

func TestSecurityPolicyContradictionMutationsAreRejected(t *testing.T) {
	t.Parallel()

	policy := readSecurityPolicy(t)
	tests := []struct {
		name     string
		anchor   string
		addition string
		wantKey  string
	}{
		{
			name:     "API path allowed without authentication",
			anchor:   "Allowed without API key:\n\n",
			addition: "- `/api/v1/*` in production mode;\n",
			wantKey:  apiAuthProtectionDecision,
		},
		{
			name:     "untrusted forwarded headers trusted",
			anchor:   "If a proxy is not trusted:\n\n",
			addition: "- forwarded IP headers are trusted;\n",
			wantKey:  forwardedHeadersDecision,
		},
		{
			name: "non-loopback metrics allowed",
			anchor: "Metrics are unauthenticated by design for Prometheus-style scraping, but they\n" +
				"must bind to localhost by default and must not be exposed to untrusted networks.\n",
			addition: "\nNon-loopback metrics listeners are allowed.\n",
			wantKey:  metricsLoopbackDecision,
		},
		{
			name:     "banned file contents copied into allowed list",
			anchor:   "Allowed:\n\n",
			addition: "- file contents;\n",
			wantKey:  logFileContentsDecision,
		},
		{
			name:     "automatic startup migrations",
			anchor:   "Requirements:\n\n",
			addition: "- automatic schema mutation runs on normal server startup;\n",
			wantKey:  separateStartupMigrationsDecision,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated, err := insertAfterUniquePolicyAnchor(policy, tt.anchor, tt.addition)
			if err != nil {
				t.Fatal(err)
			}

			violations, err := validateSecurityPolicyDecisions(mutated)
			if err != nil {
				t.Fatalf("parse mutated SECURITY.md: %v", err)
			}
			if len(violations) != 1 || violations[0] != tt.wantKey {
				t.Fatalf("violations = %v, want exactly %q", violations, tt.wantKey)
			}
		})
	}
}

func readSecurityPolicy(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "SECURITY.md"))
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func validateSecurityPolicyDecisions(markdown string) ([]string, error) {
	sections, err := parseSecurityPolicySections(markdown, securityPolicyHeadings)
	if err != nil {
		return nil, err
	}

	checklist := sections["Security Audit Checklist"]
	var violations []string

	endpoints := sections["Public and Protected Endpoints"]
	if !endpoints.hasListItem("protected surfaces", "/api/v1/* in production mode") ||
		endpoints.listContains("allowed without api key", "/api/v1/*") ||
		!checklist.hasListItem("for each security review", "confirm api auth protects production /api/v1/* mutation and import paths") {
		violations = append(violations, apiAuthProtectionDecision)
	}

	proxy := sections["Reverse Proxy and Client IP Handling"]
	if !proxy.contains("x-forwarded-for, x-forwarded-proto, and x-real-ip are trusted only when") ||
		!proxy.hasListItem("if a proxy is not trusted", "forwarded ip headers are ignored") ||
		proxy.listContains("if a proxy is not trusted", "forwarded ip headers are trusted") ||
		!checklist.hasListItem("for each security review", "confirm trusted proxy handling is not bypassed") {
		violations = append(violations, forwardedHeadersDecision)
	}

	metrics := sections["Metrics Exposure"]
	if !metrics.contains("must bind to localhost by default and must not be exposed to untrusted networks") ||
		metrics.contains("non-loopback metrics listeners are allowed") ||
		!checklist.hasListItem("for each security review", "confirm metrics exposure remains internal") {
		violations = append(violations, metricsLoopbackDecision)
	}

	logging := sections["Logging and Privacy"]
	if !logging.hasListItem("never log", "file contents") ||
		logging.hasListItem("allowed", "file contents") ||
		!checklist.hasListItem("for each security review", "confirm logs do not expose secrets, full paths, env values, or file contents") {
		violations = append(violations, logFileContentsDecision)
	}

	database := sections["Database and Migrations"]
	if !database.listContains("requirements", "migrations run through packmon-server migrate") ||
		!database.hasListItem("requirements", "no automatic schema mutation on normal server startup") ||
		database.hasContradictoryStartupMigration() ||
		!checklist.hasListItem("for each security review", "confirm migrations remain a separate command") {
		violations = append(violations, separateStartupMigrationsDecision)
	}

	return violations, nil
}

func parseSecurityPolicySections(markdown string, requiredHeadings []string) (map[string]policySection, error) {
	required := make(map[string]struct{}, len(requiredHeadings))
	for _, heading := range requiredHeadings {
		required[heading] = struct{}{}
	}

	rawSections := make(map[string][][]string, len(requiredHeadings))
	var currentHeading string
	var currentLines []string
	inFence := false
	fenceMarker := ""
	flushSection := func() {
		if _, wanted := required[currentHeading]; wanted {
			copied := append([]string(nil), currentLines...)
			rawSections[currentHeading] = append(rawSections[currentHeading], copied)
		}
		currentLines = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(markdown))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if marker := markdownFenceMarker(trimmed); marker != "" {
			if !inFence {
				inFence = true
				fenceMarker = marker
			} else if marker == fenceMarker {
				inFence = false
				fenceMarker = ""
			}
			continue
		}
		if inFence {
			continue
		}
		if heading, ok := markdownH2(line); ok {
			flushSection()
			currentHeading = heading
			continue
		}
		if currentHeading != "" {
			currentLines = append(currentLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan policy: %w", err)
	}
	flushSection()

	sections := make(map[string]policySection, len(requiredHeadings))
	for _, heading := range requiredHeadings {
		matches := rawSections[heading]
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("missing required H2 %q", heading)
		case 1:
			sections[heading] = policySection{blocks: parsePolicyBlocks(matches[0])}
		default:
			return nil, fmt.Errorf("required H2 %q occurs %d times", heading, len(matches))
		}
	}
	return sections, nil
}

func markdownFenceMarker(line string) string {
	if strings.HasPrefix(line, "```") {
		return "```"
	}
	if strings.HasPrefix(line, "~~~") {
		return "~~~"
	}
	return ""
}

func markdownH2(line string) (string, bool) {
	line = strings.TrimLeft(line, " ")
	if !strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
		return "", false
	}
	heading := strings.TrimSpace(strings.TrimPrefix(line, "## "))
	return heading, heading != ""
}

func parsePolicyBlocks(lines []string) []policyBlock {
	var blocks []policyBlock
	var parts []string
	listItem := false
	activeListLabel := ""
	flush := func() {
		if len(parts) == 0 {
			return
		}
		text := normalizePolicyText(strings.Join(parts, " "))
		block := policyBlock{text: text}
		if listItem {
			block.listLabel = activeListLabel
		}
		blocks = append(blocks, block)
		if !listItem {
			if strings.HasSuffix(text, ":") {
				activeListLabel = strings.TrimSuffix(text, ":")
			} else {
				activeListLabel = ""
			}
		}
		parts = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			flush()
			listItem = true
			parts = []string{strings.TrimPrefix(trimmed, "- ")}
			continue
		}
		if listItem && len(parts) > 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			parts = append(parts, trimmed)
			continue
		}
		if listItem && len(parts) > 0 {
			flush()
		}
		listItem = false
		parts = append(parts, trimmed)
	}
	flush()
	return blocks
}

func normalizePolicyText(text string) string {
	text = strings.ToLower(strings.ReplaceAll(text, "`", ""))
	text = strings.Join(strings.Fields(text), " ")
	return strings.TrimRight(text, ".;")
}

func (s policySection) contains(fragment string) bool {
	fragment = normalizePolicyText(fragment)
	for _, block := range s.blocks {
		if strings.Contains(block.text, fragment) {
			return true
		}
	}
	return false
}

func (s policySection) hasListItem(label, item string) bool {
	label = normalizePolicyText(label)
	item = normalizePolicyText(item)
	for _, block := range s.blocks {
		if block.listLabel == label && block.text == item {
			return true
		}
	}
	return false
}

func (s policySection) listContains(label, fragment string) bool {
	label = normalizePolicyText(label)
	fragment = normalizePolicyText(fragment)
	for _, block := range s.blocks {
		if block.listLabel == label && strings.Contains(block.text, fragment) {
			return true
		}
	}
	return false
}

func (s policySection) hasContradictoryStartupMigration() bool {
	for _, block := range s.blocks {
		if block.listLabel != "requirements" {
			continue
		}
		if strings.Contains(block.text, "automatic schema mutation") &&
			strings.Contains(block.text, "normal server startup") &&
			!strings.Contains(block.text, "no automatic schema mutation") {
			return true
		}
	}
	return false
}

func insertAfterUniquePolicyAnchor(policy, anchor, addition string) (string, error) {
	if count := strings.Count(policy, anchor); count != 1 {
		return "", fmt.Errorf("policy mutation anchor %q occurs %d times, want exactly once", anchor, count)
	}
	return strings.Replace(policy, anchor, anchor+addition, 1), nil
}
