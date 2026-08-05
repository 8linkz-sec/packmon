//go:build integration

package integration

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

const integrationCommandTimeout = 30 * time.Second

func integrationCommand(t *testing.T, name string, args ...string) (*exec.Cmd, context.Context, context.CancelFunc) {
	t.Helper()
	return integrationCommandWithTimeout(t, integrationCommandTimeout, name, args...)
}

func integrationCommandWithTimeout(t *testing.T, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.Context, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return exec.CommandContext(ctx, name, args...), ctx, cancel // #nosec G204 -- tagged tests execute fixed test binaries/tools with test-controlled arguments.
}

func integrationLongRunningCommand(t *testing.T, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	return exec.CommandContext(ctx, name, args...), cancel // #nosec G204 -- tagged tests execute fixed test binaries/tools with test-controlled arguments.
}

func failIfIntegrationCommandTimedOut(t *testing.T, ctx context.Context, timeout time.Duration, description string, output []byte) {
	t.Helper()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s timed out after %s\n%s", description, timeout, string(output))
	}
}
