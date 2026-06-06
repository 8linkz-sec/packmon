package main

import (
	"errors"
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
	if got := exitCodeForError(errors.New("plain")); got != ExitInternal {
		t.Fatalf("plain exitCodeForError() = %d, want internal", got)
	}
	if err := withExitCode(ExitOperational, nil); err != nil {
		t.Fatalf("withExitCode(nil) = %v, want nil", err)
	}
}
