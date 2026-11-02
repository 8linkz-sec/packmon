//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

const (
	listInventoryHelperModeEnv = "PACKMON_TEST_LIST_INVENTORY_HELPER"
	listInventoryHelperRootEnv = "PACKMON_TEST_LIST_INVENTORY_ROOT"
)

func TestCollectListAllInventoryPhaseRetainsValidRowsAcrossNativeDiscoveryWarnings(t *testing.T) {
	if os.Getenv(listInventoryHelperModeEnv) == "discovery-warnings" {
		runListInventoryDiscoveryWarningsHelper(t)
		return
	}

	root, err := os.MkdirTemp("", "packmon-list-inventory-")
	if err != nil {
		t.Fatalf("create helper fixture root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "blocked"), 0o700)
		_ = os.RemoveAll(root)
	})
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("make helper fixture root traversable: %v", err)
	}
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeFile(t, filepath.Join(root, "install.ps1"), "choco install git --version 2.47.0 -y\n")
	for _, path := range []string{filepath.Join(root, "Dockerfile"), filepath.Join(root, "install.ps1")} {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("make helper fixture readable: %v", err)
		}
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(blocked, "nested", "Dockerfile"), "FROM busybox:1.36\n")
	writeFile(t, filepath.Join(blocked, "nested", "config.xml"), `<config><packages><package name="blocked"/></packages></config>`)
	t.Cleanup(func() {
		_ = os.Chmod(blocked, 0o700)
	})
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatalf("chmod blocked directory: %v", err)
	}

	runListInventoryHelperProcess(t, "TestCollectListAllInventoryPhaseRetainsValidRowsAcrossNativeDiscoveryWarnings", "discovery-warnings", root, true)
}

func runListInventoryDiscoveryWarningsHelper(t *testing.T) {
	root := os.Getenv(listInventoryHelperRootEnv)
	if root == "" {
		t.Fatal("helper fixture root is empty")
	}
	blocked := filepath.Join(root, "blocked")
	if _, err := os.ReadDir(blocked); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native permission precondition failed: ReadDir(%s) error = %v", blocked, err)
	}

	var inventory listAllInventoryPhaseResult
	var err error
	stderr := captureStderr(t, func() {
		inventory, err = collectListAllInventoryPhase(scanSettings{Path: root, MaxDepth: 5}, &scanner.PackageCollection{})
	})
	if err != nil {
		t.Fatalf("collectListAllInventoryPhase() error = %v", err)
	}
	var dockerRows, chocoRows, dockerWarnings, chocoWarnings int
	for _, row := range inventory.packages {
		switch row.Ecosystem {
		case domain.EcosystemDocker:
			dockerRows++
		case domain.EcosystemChocolatey:
			chocoRows++
		}
	}
	for _, warning := range inventory.warnings {
		switch {
		case strings.HasPrefix(warning, "docker discovery warning in blocked"):
			dockerWarnings++
		case strings.HasPrefix(warning, "chocolatey discovery warning in blocked"):
			chocoWarnings++
		}
		if strings.Contains(warning, root) {
			t.Fatalf("warning leaked absolute root: %q", warning)
		}
	}
	if dockerRows != 1 || chocoRows != 1 || dockerWarnings != 1 || chocoWarnings != 1 {
		t.Fatalf("rows docker/choco=%d/%d warnings docker/choco=%d/%d; packages=%#v warnings=%#v", dockerRows, chocoRows, dockerWarnings, chocoWarnings, inventory.packages, inventory.warnings)
	}
	if strings.Contains(stderr, "\x1b") || strings.Contains(stderr, root) {
		t.Fatalf("stderr leaked terminal controls or absolute root: %q", stderr)
	}
}

func TestListInventoryCommandsReportDeletedWorkingDirectory(t *testing.T) {
	if mode := os.Getenv(listInventoryHelperModeEnv); mode == "deleted-cwd-list-all" || mode == "deleted-cwd-list-packages" {
		runListInventoryDeletedWorkingDirectoryHelper(t, mode)
		return
	}
	tests := []struct {
		name string
		mode string
	}{
		{
			name: "list_all_inventory_phase",
			mode: "deleted-cwd-list-all",
		},
		{
			name: "list_packages",
			mode: "deleted-cwd-list-packages",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runListInventoryHelperProcess(t, "TestListInventoryCommandsReportDeletedWorkingDirectory", tt.mode, "", false)
		})
	}
}

func runListInventoryDeletedWorkingDirectoryHelper(t *testing.T, mode string) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	base, err := os.MkdirTemp("", "packmon-deleted-cwd-")
	if err != nil {
		t.Fatalf("create deleted-cwd fixture: %v", err)
	}
	t.Cleanup(func() {
		if chdirErr := os.Chdir(original); chdirErr != nil {
			t.Errorf("restore original cwd: %v", chdirErr)
		}
		if removeErr := os.RemoveAll(base); removeErr != nil {
			t.Errorf("remove deleted-cwd fixture: %v", removeErr)
		}
	})
	deleted := filepath.Join(base, "deleted")
	if err := os.Mkdir(deleted, 0o750); err != nil {
		t.Fatalf("create deleted current directory: %v", err)
	}
	if err := os.Chdir(deleted); err != nil {
		t.Fatalf("enter deleted current directory: %v", err)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatalf("remove current directory: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Fatal("Getwd() succeeded after current directory deletion")
	}

	var runErr error
	switch mode {
	case "deleted-cwd-list-all":
		_, runErr = collectListAllInventoryPhase(scanSettings{Path: ".", MaxDepth: 2}, &scanner.PackageCollection{})
	case "deleted-cwd-list-packages":
		runErr = runListPackagesWithSettings(scanSettings{Path: ".", MaxDepth: 2})
	default:
		t.Fatalf("unknown deleted-cwd helper mode %q", mode)
	}
	if runErr == nil || exitCodeForError(runErr) != ExitOperational {
		t.Fatalf("error = %v, want operational exit %d", runErr, ExitOperational)
	}
	message := strings.ToLower(runErr.Error())
	if !strings.Contains(message, "resolve path") && !strings.Contains(message, "working directory") && !strings.Contains(message, "getwd") {
		t.Fatalf("error = %q, want cwd/path resolution context", runErr)
	}
}

func runListInventoryHelperProcess(t *testing.T, testName, mode, root string, unprivileged bool) {
	t.Helper()
	timeout := 30 * time.Second
	if deadline, ok := t.Deadline(); ok {
		remaining := time.Until(deadline) - time.Second
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		t.Fatal("no time remains for helper process")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	executable := os.Args[0]
	if unprivileged && os.Geteuid() == 0 {
		executable = copyListInventoryHelperExecutable(t)
	}
	//nolint:gosec // The test re-executes its own binary with a fixed test name.
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+testName+"$", "-test.count=1", "-test.v")
	cmd.Env = listInventoryHelperEnvironment(mode, root)
	if unprivileged && os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("helper process timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, output)
	}
}

func copyListInventoryHelperExecutable(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "packmon-list-inventory-helper-")
	if err != nil {
		t.Fatalf("create unprivileged helper directory: %v", err)
	}
	t.Cleanup(func() {
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			t.Errorf("remove unprivileged helper directory: %v", removeErr)
		}
	})
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("make unprivileged helper directory traversable: %v", err)
	}

	source, err := os.Open(os.Args[0]) // #nosec G304 -- the test copies its own executable.
	if err != nil {
		t.Fatalf("open test executable: %v", err)
	}
	defer source.Close()
	destinationPath := filepath.Join(dir, "packmon.test")
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) // #nosec G304,G306 -- an executable copy is required for the dropped-privilege helper.
	if err != nil {
		t.Fatalf("create helper executable: %v", err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatalf("copy helper executable: %v", err)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("close helper executable: %v", err)
	}
	return destinationPath
}

func listInventoryHelperEnvironment(mode, root string) []string {
	prefixes := []string{listInventoryHelperModeEnv + "=", listInventoryHelperRootEnv + "="}
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		keep := true
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry, prefix) {
				keep = false
				break
			}
		}
		if keep {
			env = append(env, entry)
		}
	}
	return append(env, listInventoryHelperModeEnv+"="+mode, listInventoryHelperRootEnv+"="+root)
}
