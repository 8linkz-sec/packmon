package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/scanner"
)

// overflowingTimeoutSeconds is one second past the largest whole-second
// time.Duration; multiplied by time.Second it wraps into a negative, already
// expired timeout.
const overflowingTimeoutSeconds = overflowingDBSyncTimeoutSeconds

// wrappingPositiveTimeoutSeconds overflows time.Duration all the way around to
// a small positive value (about 0.29s), so a "<= 0" check after the
// multiplication does not catch it.
const wrappingPositiveTimeoutSeconds = "18446744074"

func overflowingTimeoutInt(t *testing.T) int {
	t.Helper()
	return timeoutSecondsInt(t, overflowingTimeoutSeconds)
}

func timeoutSecondsInt(t *testing.T, raw string) int {
	t.Helper()
	skipUnless64BitInt(t)
	v, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("parse overflowing timeout: %v", err)
	}
	return v
}

func TestTimeoutSecondsDurationBounds(t *testing.T) {
	skipUnless64BitInt(t)

	if got, err := timeoutSecondsDuration("timeout", 30); err != nil || got != 30*time.Second {
		t.Fatalf("timeoutSecondsDuration(30) = %s, %v; want 30s, nil", got, err)
	}
	if got, err := timeoutSecondsDuration("timeout", int(maxTimeoutSeconds)); err != nil || got != time.Duration(maxTimeoutSeconds)*time.Second {
		t.Fatalf("timeoutSecondsDuration(max) = %s, %v; want max, nil", got, err)
	}
	for _, seconds := range []int{0, -1} {
		if _, err := timeoutSecondsDuration("timeout", seconds); err == nil || !strings.Contains(err.Error(), "timeout must be greater than zero") {
			t.Fatalf("timeoutSecondsDuration(%d) error = %v, want non-positive rejection", seconds, err)
		}
	}
	for _, raw := range []string{overflowingTimeoutSeconds, wrappingPositiveTimeoutSeconds} {
		_, err := timeoutSecondsDuration("PACKMON_TIMEOUT", timeoutSecondsInt(t, raw))
		if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT must be at most 9223372036 seconds") {
			t.Fatalf("timeoutSecondsDuration(%s) error = %v, want upper-bound rejection", raw, err)
		}
	}
}

func TestResolveScanSettingsRejectsOverflowingTimeoutFlag(t *testing.T) {
	skipUnless64BitInt(t)
	t.Setenv("PACKMON_TIMEOUT", "")

	cmd := newScanCmd()
	mustSetFlag(t, cmd, "timeout", overflowingTimeoutSeconds)
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: overflowingTimeoutInt(t), APIKey: "flag"}
	_, err := resolveScanSettings(cmd, nil, scanTarget{Path: "."}, flags)
	if err == nil || !strings.Contains(err.Error(), "timeout must be at most 9223372036 seconds") {
		t.Fatalf("resolveScanSettings() error = %v, want overflowing --timeout rejection", err)
	}
}

func TestResolveScanSettingsRejectsOverflowingTimeoutEnv(t *testing.T) {
	skipUnless64BitInt(t)
	t.Setenv("PACKMON_TIMEOUT", overflowingTimeoutSeconds)

	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 30, APIKey: "flag"}
	_, err := resolveScanSettings(newScanCmd(), nil, scanTarget{Path: "."}, flags)
	if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT must be at most 9223372036 seconds") {
		t.Fatalf("resolveScanSettings() error = %v, want overflowing PACKMON_TIMEOUT rejection", err)
	}
}

func TestResolveScanSettingsRejectsOverflowingTimeoutConfig(t *testing.T) {
	t.Setenv("PACKMON_TIMEOUT", "")
	overflowing := overflowingTimeoutInt(t)
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 30, APIKey: "flag"}

	_, err := resolveScanSettings(newScanCmd(), &cliConfig{Timeout: overflowing}, scanTarget{Path: "."}, flags)
	if err == nil || !strings.Contains(err.Error(), "timeout must be at most 9223372036 seconds") {
		t.Fatalf("resolveScanSettings(config) error = %v, want overflowing config timeout rejection", err)
	}

	target := scanTarget{Path: ".", Repo: &cliRepoConfig{Name: "app", Path: ".", Timeout: overflowing}}
	_, err = resolveScanSettings(newScanCmd(), nil, target, flags)
	if err == nil || !strings.Contains(err.Error(), "timeout must be at most 9223372036 seconds") {
		t.Fatalf("resolveScanSettings(repo) error = %v, want overflowing repo timeout rejection", err)
	}
}

func TestResolveScanSettingsAcceptsLargestRepresentableTimeout(t *testing.T) {
	skipUnless64BitInt(t)
	t.Setenv("PACKMON_TIMEOUT", "")

	cmd := newScanCmd()
	mustSetFlag(t, cmd, "timeout", "9223372036")
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 9223372036, APIKey: "flag"}
	settings, err := resolveScanSettings(cmd, nil, scanTarget{Path: "."}, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings() error = %v", err)
	}
	cfg := buildScannerConfig(settings, nil, "CRITICAL", scanner.Mode("local"))
	if want := 9223372036 * time.Second; cfg.Timeout != want {
		t.Fatalf("scanner timeout = %s, want %s", cfg.Timeout, want)
	}
	if got := buildAutoSBOMConfig(settings, autoSBOMFlags{}).Timeout; got != 9223372036*time.Second {
		t.Fatalf("auto SBOM timeout = %s, want %s", got, 9223372036*time.Second)
	}
}

func TestLoadCLIConfigRejectsOverflowingTimeouts(t *testing.T) {
	skipUnless64BitInt(t)

	for _, tt := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "top level", yaml: "timeout: " + overflowingTimeoutSeconds + "\n", want: "timeout must be at most 9223372036 seconds"},
		{name: "repo", yaml: "repos:\n  - path: .\n    timeout: " + overflowingTimeoutSeconds + "\n", want: "repos[0].timeout must be at most 9223372036 seconds"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".packmon.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, _, err := loadCLIConfig(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadCLIConfig() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestEffectiveConfigShowSettingsRejectsOverflowingTimeoutEnv(t *testing.T) {
	skipUnless64BitInt(t)
	t.Setenv("PACKMON_TIMEOUT", overflowingTimeoutSeconds)

	_, err := effectiveConfigShowSettings(&cliConfig{})
	if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT must be at most 9223372036 seconds") {
		t.Fatalf("effectiveConfigShowSettings() error = %v, want overflowing PACKMON_TIMEOUT rejection", err)
	}
}

func TestRegistryLookupPhaseIgnoresOverflowingTimeout(t *testing.T) {
	for _, raw := range []string{overflowingTimeoutSeconds, wrappingPositiveTimeoutSeconds} {
		_, phase := withRegistryLookupPhase(context.Background(), timeoutSecondsInt(t, raw))
		if got := phase.perRequestTimeout(); got != defaultPerRequestLookupTimeout {
			t.Fatalf("perRequestTimeout(%s) = %s, want default %s for an unrepresentable timeout", raw, got, defaultPerRequestLookupTimeout)
		}
	}
}
