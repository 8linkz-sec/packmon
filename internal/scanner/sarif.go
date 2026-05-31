package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/8linkz/packmon/internal/domain"
)

// SARIF 2.1.0 types.
// See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	InformationURI string            `json:"informationUri"`
	Rules          []sarifRule       `json:"rules"`
	Properties     map[string]string `json:"properties,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// SARIFWriter converts scan results to SARIF 2.1.0 JSON.
type SARIFWriter struct {
	toolVersion string
}

// NewSARIFWriter creates a SARIFWriter with the given packmon version string.
func NewSARIFWriter(toolVersion string) *SARIFWriter {
	if toolVersion == "" {
		toolVersion = "dev"
	}
	return &SARIFWriter{toolVersion: toolVersion}
}

// Write serializes the scan result as SARIF 2.1.0 JSON and writes it to w.
func (sw *SARIFWriter) Write(w io.Writer, result *domain.ScanResult) error {
	log := sw.buildSARIF(result)

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif: marshal: %w", err)
	}

	_, err = w.Write(data)
	return err
}

// WriteFile writes the SARIF output to the given file path.
func (sw *SARIFWriter) WriteFile(path string, result *domain.ScanResult) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("sarif: create file %s: %w", path, err)
	}

	if err := sw.Write(f, result); err != nil {
		closeSilently(f)
		return err
	}
	return f.Close()
}

func (sw *SARIFWriter) buildSARIF(result *domain.ScanResult) sarifLog {
	// Collect unique rules from findings.
	ruleIndex := make(map[string]int) // ruleID -> index
	var rules []sarifRule

	for _, f := range result.Findings {
		ruleID := sw.ruleID(f)
		if _, exists := ruleIndex[ruleID]; exists {
			continue
		}
		ruleIndex[ruleID] = len(rules)
		rules = append(rules, sw.buildRule(f, ruleID))
	}

	// Build results.
	results := make([]sarifResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		results = append(results, sw.buildResult(f))
	}

	return sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "packmon",
						Version:        sw.toolVersion,
						InformationURI: "https://github.com/8linkz/packmon",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

func (sw *SARIFWriter) ruleID(f domain.Finding) string {
	if f.AdvisoryID != "" {
		return f.AdvisoryID
	}
	if f.RiskType != "" {
		return f.RiskType
	}
	return "unknown"
}

func (sw *SARIFWriter) buildRule(f domain.Finding, ruleID string) sarifRule {
	var tags []string
	tags = append(tags, string(f.Ecosystem))
	tags = append(tags, string(f.Type))
	if f.Source != "" {
		tags = append(tags, f.Source)
	}

	rule := sarifRule{
		ID:               ruleID,
		ShortDescription: sarifMessage{Text: f.Title},
		Properties:       sarifRuleProperties{Tags: tags},
	}
	if f.URL != "" {
		rule.HelpURI = f.URL
	}
	return rule
}

func (sw *SARIFWriter) buildResult(f domain.Finding) sarifResult {
	ruleID := sw.ruleID(f)
	level := sw.sarifLevel(f)

	msg := fmt.Sprintf("%s@%s (%s): %s", f.Name, f.Version, f.Ecosystem, f.Title)
	if f.FixedVersion != "" {
		msg += fmt.Sprintf(" [fix: %s]", f.FixedVersion)
	}

	return sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifMessage{Text: msg},
	}
}

// sarifLevel maps packmon severity to SARIF level.
// SARIF levels: "error", "warning", "note", "none".
// Malicious and supply-chain risk findings are always "error".
func (sw *SARIFWriter) sarifLevel(f domain.Finding) string {
	if isAlwaysBlockingFinding(f) {
		return "error"
	}
	switch f.Severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	case domain.SeverityLow:
		return "note"
	default:
		return "note"
	}
}
