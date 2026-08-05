package feed

import "github.com/8linkz-sec/packmon/internal/logsafe"

const maxFeedDiagnosticBytes = 1024

// SafeDiagnosticError formats feed-sync errors for persistent server logs and
// feed status rows. It preserves the failure class while removing local paths,
// credential-bearing URLs, bearer tokens, and secret-like assignments.
func SafeDiagnosticError(err error) string {
	if err == nil {
		return ""
	}
	return SafeDiagnosticMessage(err.Error())
}

// SafeDiagnosticMessage is SafeDiagnosticError for already-rendered diagnostic
// text such as subprocess stderr.
func SafeDiagnosticMessage(raw string) string {
	return logsafe.BoundedDiagnosticValue(raw, maxFeedDiagnosticBytes)
}
