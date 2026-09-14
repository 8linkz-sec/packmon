package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseBoolLiteralAcceptsDocumentedForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "true", want: true},
		{raw: "TRUE", want: true},
		{raw: " Yes ", want: true},
		{raw: "1", want: true},
		{raw: "false", want: false},
		{raw: "FALSE", want: false},
		{raw: " No ", want: false},
		{raw: "0", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseBoolLiteral(tc.raw)
			if err != nil {
				t.Fatalf("parseBoolLiteral(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseBoolLiteral(%q) = %t, want %t", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseBoolLiteralRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "enabled", "2", "true-ish"} {
		if got, err := parseBoolLiteral(raw); err == nil || got {
			t.Errorf("parseBoolLiteral(%q) = (%t, %v), want (false, error)", raw, got, err)
		}
	}
}

func TestStrictEnvBoolDistinguishesUnsetEmptyValidAndInvalid(t *testing.T) {
	const key = "PACKMON_TEST_F047_STRICT_BOOL"
	const sentinel = "not-a-boolean-sentinel"

	cases := []struct {
		name    string
		value   string
		want    bool
		present bool
		wantErr bool
	}{
		{name: "unset", want: false, present: false},
		{name: "empty", value: "", want: false, present: false},
		{name: "whitespace", value: " \t ", want: false, present: false},
		{name: "mixed case true", value: "TrUe", want: true, present: true},
		{name: "padded yes", value: " yes ", want: true, present: true},
		{name: "false", value: "false", want: false, present: true},
		{name: "zero", value: "0", want: false, present: true},
		{name: "no", value: "no", want: false, present: true},
		{name: "malformed", value: sentinel, want: false, present: true, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "unset" {
				t.Setenv(key, "previous-value")
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("unset %s: %v", key, err)
				}
			} else {
				t.Setenv(key, tc.value)
			}

			got, present, err := strictEnvBool(key)
			if got != tc.want || present != tc.present {
				t.Fatalf("strictEnvBool(%q) = (%t, %t, %v), want (%t, %t, error=%t)", key, got, present, err, tc.want, tc.present, tc.wantErr)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("strictEnvBool(%q) error = %v, want error=%t", key, err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), sentinel) {
				t.Fatalf("strictEnvBool(%q) error leaks environment value %q: %v", key, sentinel, err)
			}
		})
	}
}
