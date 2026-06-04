package scanner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestSARIFSurfacesParseErrorsAsNotifications(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		FindingsCount:   0,
		ParseErrors: []string{
			"package-lock.json: unexpected end of JSON input",
			"go.mod: malformed require block",
		},
	}

	var out bytes.Buffer
	if err := NewSARIFWriter("1.2.3").Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var log struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool `json:"executionSuccessful"`
				ToolExecutionNotifications []struct {
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, out.String())
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Invocations) != 1 {
		t.Fatalf("expected one run with one invocation, got %+v", log.Runs)
	}
	notes := log.Runs[0].Invocations[0].ToolExecutionNotifications
	if len(notes) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(notes))
	}
	if !strings.Contains(notes[0].Message.Text, "package-lock.json") {
		t.Fatalf("notification missing parse error text: %q", notes[0].Message.Text)
	}
	if notes[0].Level != "warning" {
		t.Fatalf("expected warning level, got %q", notes[0].Level)
	}
}

func TestSARIFOmitsInvocationsWithoutParseErrors(t *testing.T) {
	result := &domain.ScanResult{Mode: "local", PackagesScanned: 1}
	var out bytes.Buffer
	if err := NewSARIFWriter("dev").Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if strings.Contains(out.String(), "invocations") {
		t.Fatalf("did not expect invocations block without parse errors\n%s", out.String())
	}
}
