package main

import (
	"errors"
	"fmt"
	"os"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitCodeForError(err))
	}
}

type exitCodeError struct {
	code int
	err  error
}

func (e exitCodeError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e exitCodeError) Unwrap() error {
	return e.err
}

func (e exitCodeError) Code() int {
	if e.code == ExitOK {
		return ExitOperational
	}
	return e.code
}

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return exitCodeError{code: code, err: err}
}

func exitCodeForError(err error) int {
	var codeErr exitCodeError
	if errors.As(err, &codeErr) {
		return codeErr.Code()
	}
	return ExitInternal
}
