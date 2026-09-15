package termtext

import (
	"strings"
	"testing"
)

func TestSanitizeNeutralizesTerminalControls(t *testing.T) {
	input := "pkg\x1b]8;;https://evil.example\a\n::warning::spoof\r\tok\u202e"

	got := Sanitize(input)
	for _, blocked := range []string{"\x1b", "\a", "\n::warning::", "\r", "\t", "\u202e"} {
		if strings.Contains(got, blocked) {
			t.Fatalf("Sanitize() left blocked sequence %q in %q", blocked, got)
		}
	}
	for _, want := range []string{`pkg`, `\x1B`, `\x07`, `\n::warning::spoof`, `\r`, `\t`, `\u202E`} {
		if !strings.Contains(got, want) {
			t.Fatalf("Sanitize() = %q, want visible escape %q", got, want)
		}
	}
}

func TestSanitizePreservesPrintableTextAndEscapesC1Controls(t *testing.T) {
	input := "package\u0085name\u009f"

	if got, want := Sanitize(input), `package\u0085name\u009F`; got != want {
		t.Fatalf("Sanitize() = %q, want %q", got, want)
	}
}

func TestSanitizeEmptyInput(t *testing.T) {
	if got := Sanitize(""); got != "" {
		t.Fatalf("Sanitize(empty) = %q, want empty string", got)
	}
}
