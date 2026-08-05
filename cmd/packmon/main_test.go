package main

import (
	"errors"
	"io"
	"testing"
)

func TestExitCodeErrorHelpers(t *testing.T) {
	t.Parallel()

	base := errors.New("scan failed")
	err := withExitCode(ExitBlocking, base)
	if err == nil {
		t.Fatal("withExitCode returned nil for non-nil error")
	}
	if got := err.Error(); got != base.Error() {
		t.Fatalf("Error() = %q, want %q", got, base.Error())
	}
	var codeErr exitCodeError
	if !errors.As(err, &codeErr) {
		t.Fatalf("error %T does not unwrap as exitCodeError", err)
	}
	if !errors.Is(err, base) {
		t.Fatalf("error does not unwrap base error")
	}
	if got := codeErr.Code(); got != ExitBlocking {
		t.Fatalf("Code() = %d, want %d", got, ExitBlocking)
	}
	if got := exitCodeForError(err); got != ExitBlocking {
		t.Fatalf("exitCodeForError() = %d, want %d", got, ExitBlocking)
	}

	okCodeErr := exitCodeError{code: ExitOK, err: base}
	if got := okCodeErr.Code(); got != ExitOperational {
		t.Fatalf("Code() with ExitOK = %d, want operational fallback", got)
	}
	empty := exitCodeError{}
	if got := empty.Error(); got != "" {
		t.Fatalf("empty Error() = %q, want empty", got)
	}
	if got := exitCodeForError(errors.New("plain")); got != ExitOperational {
		t.Fatalf("plain exitCodeForError() = %d, want operational", got)
	}
	if err := withExitCode(ExitOperational, nil); err != nil {
		t.Fatalf("withExitCode(nil) = %v, want nil", err)
	}
}

func TestUsageErrorsUseOperationalExitCode(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown command", args: []string{"no-such-command"}},
		{name: "unknown scan flag", args: []string{"scan", "--no-such-flag"}},
		{name: "too many scan args", args: []string{"scan", "one", "two"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Execute() error = nil, want usage error")
			}
			if got := exitCodeForError(err); got != ExitOperational {
				t.Fatalf("exitCodeForError(%v) = %d, want operational", tt.args, got)
			}
		})
	}
}
