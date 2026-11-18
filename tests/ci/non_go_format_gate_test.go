package ci

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNonGoFormatGateLineEndingPolicy runs scripts/check-non-go-format.sh over
// a throwaway Git checkout holding one fixture file per case. PowerShell
// scripts are checked out with CRLF (.gitattributes `*.ps1 text eol=crlf`), so
// the gate must accept consistent CRLF there while still rejecting bare CR,
// mixed endings and trailing whitespace hidden before the CR; every other
// checked file stays LF-only.
func TestNonGoFormatGateLineEndingPolicy(t *testing.T) {
	t.Parallel()

	bash, git := requireNonGoFormatGateTools(t)
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-non-go-format.sh"))
	if err != nil {
		t.Fatalf("read scripts/check-non-go-format.sh: %v", err)
	}

	for _, tc := range []struct {
		name     string
		file     string
		content  string
		wantPass bool
		wantMsg  string
	}{
		{name: "crlf ps1 passes", file: "tool.ps1", content: "Write-Host 'a'\r\nWrite-Host 'b'\r\n", wantPass: true},
		{name: "lf ps1 passes", file: "tool.ps1", content: "Write-Host 'a'\nWrite-Host 'b'\n", wantPass: true},
		{name: "mixed ps1 fails", file: "tool.ps1", content: "Write-Host 'a'\r\nWrite-Host 'b'\n", wantMsg: "tool.ps1: contains bare CR or mixed line endings"},
		{name: "bare cr ps1 fails", file: "tool.ps1", content: "Write-Host 'a'\rWrite-Host 'b'\r\n", wantMsg: "tool.ps1: contains bare CR or mixed line endings"},
		{name: "crlf ps1 trailing whitespace fails", file: "tool.ps1", content: "Write-Host 'a' \r\n", wantMsg: "tool.ps1: contains trailing whitespace"},
		{name: "lf sh passes", file: "tool.sh", content: "echo a\necho b\n", wantPass: true},
		{name: "crlf sh fails", file: "tool.sh", content: "echo a\r\necho b\r\n", wantMsg: "tool.sh: contains CRLF or bare CR line endings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := newNonGoFormatGateFixture(t, git, script, tc.file, tc.content)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, filepath.Join(dir, "scripts", "check-non-go-format.sh")) // #nosec G204 -- absolute bash path and test-owned fixture script.
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if tc.wantPass {
				if err != nil {
					t.Fatalf("gate rejected %s: %v\n%s", tc.file, err, out)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("gate on %s: err = %v, want exit status 1\n%s", tc.file, err, out)
			}
			if !strings.Contains(string(out), tc.wantMsg) {
				t.Fatalf("gate output on %s missing %q:\n%s", tc.file, tc.wantMsg, out)
			}
		})
	}
}

func requireNonGoFormatGateTools(t *testing.T) (bash, git string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the non-Go format gate runs under bash; covered by the focused Linux test command")
	}
	var err error
	if bash, err = exec.LookPath("bash"); err != nil {
		t.Skipf("bash is unavailable: %v", err)
	}
	if git, err = exec.LookPath("git"); err != nil {
		t.Skipf("git is unavailable: %v", err)
	}
	return bash, git
}

// newNonGoFormatGateFixture builds a Git checkout holding a copy of the gate
// script and one tracked fixture file written byte for byte, so the gate sees
// exactly the line endings under test.
func newNonGoFormatGateFixture(t *testing.T, git string, script []byte, file, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o750); err != nil {
		t.Fatalf("create fixture scripts dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "check-non-go-format.sh"), script, 0o600); err != nil { // #nosec G703 -- test-owned temporary fixture path.
		t.Fatalf("write fixture gate script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil { // #nosec G306 -- test-owned temporary fixture.
		t.Fatalf("write fixture %s: %v", file, err)
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "add", "--", "scripts/check-non-go-format.sh", file},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, git, args...) // #nosec G204 -- absolute git path with fixed arguments.
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}
