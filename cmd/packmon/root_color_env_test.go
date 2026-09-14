package main

import (
	"os"
	"testing"
)

func TestDefaultNoColorEnvironmentMatrix(t *testing.T) {
	cases := []struct {
		name           string
		packmonNoColor string
		noColor        string
		want           bool
	}{
		{name: "both empty", want: false},
		{name: "packmon true", packmonNoColor: "true", want: true},
		{name: "packmon one", packmonNoColor: "1", want: true},
		{name: "packmon yes", packmonNoColor: "yes", want: true},
		{name: "packmon false", packmonNoColor: "false", want: false},
		{name: "packmon false no color set", packmonNoColor: "false", noColor: "1", want: true},
		{name: "no color whitespace", noColor: " \t ", want: false},
		{name: "no color value", noColor: "0", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PACKMON_NO_COLOR", tc.packmonNoColor)
			t.Setenv("NO_COLOR", tc.noColor)
			if got := defaultNoColor(); got != tc.want {
				t.Fatalf("defaultNoColor() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestEnvOrDefaultUsesFallbackWhenVariableIsUnset(t *testing.T) {
	const key = "PACKMON_TEST_F047_ENV_OR_DEFAULT_UNSET"
	t.Setenv(key, "inherited-value")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	if got := envOrDefault(key, "fallback"); got != "fallback" {
		t.Fatalf("envOrDefault(unset) = %q, want fallback", got)
	}
}
