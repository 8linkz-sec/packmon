package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// TestPrometheusIncreaseAlertsFireOnSingleEvents pins the timing of the
// starter alerts built on increase(counter[R]) > 0. A single increment keeps
// that expression true for at most R, so a pending `for` duration of R or
// longer means an isolated event never fires -- although the descriptions
// promise an at-least-one-event signal. The pending duration must therefore
// stay strictly shorter than the smallest increase() range in the rule.
func TestPrometheusIncreaseAlertsFireOnSingleEvents(t *testing.T) {
	t.Parallel()

	rel := filepath.Join("docs", "monitoring", "packmon-alerts.yml")
	data, err := os.ReadFile(filepath.Join("..", "..", rel)) //nolint:gosec // static repository documentation fixture path.
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var rules prometheusRulesFile
	if err := yaml.Unmarshal(data, &rules); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}

	increaseRange := regexp.MustCompile(`increase\([^\[\)]*\[([0-9]+[smh])\]\)`)
	checked := 0
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			matches := increaseRange.FindAllStringSubmatch(rule.Expr, -1)
			if len(matches) == 0 {
				continue
			}
			pending, err := time.ParseDuration(rule.For)
			if err != nil {
				t.Fatalf("%s alert %s for = %q: %v", rel, rule.Alert, rule.For, err)
			}
			for _, match := range matches {
				window, err := time.ParseDuration(match[1])
				if err != nil {
					t.Fatalf("%s alert %s range %q: %v", rel, rule.Alert, match[1], err)
				}
				if pending >= window {
					t.Fatalf("%s alert %s waits for %s on an increase over %s; a single event leaves the range before the alert fires", rel, rule.Alert, pending, window)
				}
			}
			checked++
		}
	}
	// PackmonMetricsStoreReadFailure, PackmonDegradedResponses and
	// PackmonQueueErrors are the event-counter alerts this contract protects.
	if checked < 3 {
		t.Fatalf("%s: checked %d increase() alerts, want at least 3", rel, checked)
	}
}
