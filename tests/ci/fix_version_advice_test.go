package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFixVersionAdviceStaysVersionAware guards against reintroducing a defect
// that shipped once already: user-facing fix advice was derived from the *lowest*
// fixed version anywhere in an advisory rather than from the range the installed
// version actually falls in.
//
// For an advisory that patched a flaw on several release branches -- one range
// per branch, the common shape -- the lowest fix is below the version the user
// already runs. The advice then reads as "you are already patched" when they are
// not, which is the worst possible way for a security scanner to be wrong.
//
// The version-aware answer comes from version.ExtractFixedVersionFor. Its
// version-blind counterpart, version.ExtractFixedVersion, survives only as that
// function's fallback for versions outside every range. This test pins that: no
// production code outside internal/version may call the blind variant.
func TestFixVersionAdviceStaysVersionAware(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	var offenders []string

	err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".gotmp", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// internal/version owns both functions and legitimately calls the blind
		// one as the documented fallback.
		if strings.Contains(filepath.ToSlash(path), "/internal/version/") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // repository walk over checked-in sources
		if readErr != nil {
			return readErr
		}
		for lineNumber, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			// Match the blind call without matching the version-aware "...For(".
			for _, blind := range []string{"ExtractFixedVersion(", "ExtractFixedVersionConstraint("} {
				if strings.Contains(line, blind) {
					offenders = append(offenders,
						filepath.ToSlash(path)+":"+itoa(lineNumber+1)+" calls "+strings.TrimSuffix(blind, "("))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("production code derives fix advice from the version-blind helper:\n  %s\n\n"+
			"Use version.ExtractFixedVersionFor / ExtractFixedVersionConstraintFor instead: they select\n"+
			"the fix from the range the installed version falls in. See internal/version/fixed_for_version.go.",
			strings.Join(offenders, "\n  "))
	}
}

// TestFixVersionAdviceHelperIsDocumentedAsTheFallback keeps the warning on the
// blind helper in place. Without it the next caller has no signal at the call
// site, and this guard becomes the only thing standing between them and the
// defect.
func TestFixVersionAdviceHelperIsDocumentedAsTheFallback(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "version", "compare.go")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read compare.go: %v", err)
	}
	source := string(data)

	for _, want := range []string{
		"Do NOT use this for user-facing fix advice",
		"ExtractFixedVersionFor",
		"TestFixVersionAdviceStaysVersionAware",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("internal/version/compare.go lost the fallback warning marker %q", want)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
