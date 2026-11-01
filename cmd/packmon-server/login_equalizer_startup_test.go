package main

import (
	"os"
	"strings"
	"testing"
)

// TestRunPreparesLoginEqualizerBeforeServing keeps the dummy-hash generation
// for login timing equalization on the startup path: generated lazily, the
// first failed login would pay for a generation plus a comparison and
// concurrent first logins would wait on it. The check is static because run()
// opens the HTTP listener.
func TestRunPreparesLoginEqualizerBeforeServing(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("ReadFile(main.go) error = %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func run() error {")
	if start < 0 {
		t.Fatal("main.go has no run() function")
	}
	body := text[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	prepare := strings.Index(body, "auth.PrepareLoginEqualizer()")
	build := strings.Index(body, "buildRuntimeServer(")
	if prepare < 0 || build < 0 || prepare > build {
		t.Fatalf("run() must call auth.PrepareLoginEqualizer() before buildRuntimeServer (prepare at %d, build at %d)", prepare, build)
	}
}
