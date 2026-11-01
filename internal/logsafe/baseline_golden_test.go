package logsafe

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateBaselineGolden = flag.Bool("update-baseline-golden", false,
	"rewrite testdata/baseline_golden.json from baselineRedactDiagnosticMessage")

const baselineGoldenPath = "testdata/baseline_golden.json"

// goldenCase is one message and the output of the redaction as it stood
// before the extended scan.
type goldenCase struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

// plantedFragmentPattern matches the planted values of the golden inputs.
var plantedFragmentPattern = regexp.MustCompile(`zq\d{4}`)

// baselineGoldenFragments are the pieces the golden inputs are built from:
// keys, separators, quotes and escapes, delimiters, paths, URLs, and the
// markers of the other rules.
var baselineGoldenFragments = []string{
	"password", "token", "PGPASSWORD", "api_key", "secret", "tokens", "auth",
	"cookie", "Cookie", "set-cookie", "session_id", "Authorization", "db.password",
	`"Client Secret"`, "credentials", "AccountKey", "passphrase", "--password", "-p",
	":", ": ", "=", " = ", "%3D", ":\t",
	`"`, `'`, `\"`, `\\"`, `\\\"`, `\`, "&quot;", "&#39;",
	"{", "}", "[", "]", ",", ";", "&", " ", " ", " ", "\n", "!", ".",
	`C:\Users\a\b\c.txt`, "/home/a/b/c", "https://u:p@example.test/x?token=y",
	"Bearer ", "Basic ", "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
	"x", "label", "0", "it's",
}

// baselineGoldenInputs returns the golden inputs: hand-picked messages and a
// fixed pseudo-random mix of fragments, each value a unique planted zqNNNN.
func baselineGoldenInputs() []string {
	inputs := []string{
		`"x password: a" PGPASSWORD:"0 s 0"`,
		`prompt "passwd: " PGPASSWORD:"0 quote-secret-2 0"`,
		`{\"token\":"ghp_zq0001"}`,
		`unmatched " here password="!zq0002"`,
		`read token from Bearer C:\Users\alice\zq0003\token.txt failed`,
		`Bearer sig="zq0004 a b"`,
		`-----BEGIN PRIVATE KEY----- password: {-----END PRIVATE KEY-----zq0005"x password: PGPASSWORD-----END PRIVATE KEY-----"`,
		`he said "hello password=zq0006"!zq0007`,
		`A:\0\!"Apikey:0":\""zq0008`,
	}
	rng := rand.New(rand.NewPCG(64, 66)) //nolint:gosec // a fixed seed makes the golden inputs reproducible; nothing secret is drawn.
	planted := 100
	for range 1200 {
		var b strings.Builder
		for range 3 + rng.IntN(10) {
			if rng.IntN(4) == 0 {
				fmt.Fprintf(&b, "zq%04d", planted)
				planted++
				continue
			}
			b.WriteString(baselineGoldenFragments[rng.IntN(len(baselineGoldenFragments))])
		}
		inputs = append(inputs, b.String())
	}
	return inputs
}

// TestBaselineRedactionMatchesGolden pins the baseline: the redaction as it
// stood before the extended scan must still produce the outputs recorded in
// testdata/baseline_golden.json, so a change to a helper the baseline shares
// with the extended scan cannot silently change the baseline, and
// RedactDiagnosticMessage must hide every planted value the recorded output
// hides. Regenerate the fixture with -update-baseline-golden only when the
// baseline is meant to change.
func TestBaselineRedactionMatchesGolden(t *testing.T) {
	t.Parallel()

	if *updateBaselineGolden {
		var cases []goldenCase
		for _, in := range baselineGoldenInputs() {
			cases = append(cases, goldenCase{In: in, Out: baselineRedactDiagnosticMessage(in)})
		}
		data, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash(baselineGoldenPath), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(filepath.FromSlash(baselineGoldenPath))
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 1000 {
		t.Fatalf("golden fixture holds %d cases, want at least 1000", len(cases))
	}
	for _, c := range cases {
		if got := baselineRedactDiagnosticMessage(c.In); got != c.Out {
			t.Errorf("baselineRedactDiagnosticMessage(%q) =\n%q\nwant the recorded\n%q", c.In, got, c.Out)
			continue
		}
		got := RedactDiagnosticMessage(c.In)
		for _, planted := range plantedFragmentPattern.FindAllString(c.In, -1) {
			if !strings.Contains(c.Out, planted) && strings.Contains(got, planted) {
				t.Errorf("RedactDiagnosticMessage(%q) = %q reveals %s, which the baseline hides", c.In, got, planted)
			}
		}
	}
}
