//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

func TestCollectListAllInventoryPhaseRetainsValidRowsAcrossNativeDiscoveryWarnings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeFile(t, filepath.Join(root, "install.ps1"), "choco install git --version 2.47.0 -y\n")
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
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "list_all_inventory_phase",
			run: func() error {
				_, runErr := collectListAllInventoryPhase(scanSettings{Path: ".", MaxDepth: 2}, &scanner.PackageCollection{})
				return runErr
			},
		},
		{
			name: "list_packages",
			run: func() error {
				return runListPackagesWithSettings(scanSettings{Path: ".", MaxDepth: 2})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleted := filepath.Join(t.TempDir(), "deleted-cwd")
			if err := os.Mkdir(deleted, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(deleted); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(deleted); err != nil {
				_ = os.Chdir(original)
				t.Fatalf("remove current directory: %v", err)
			}
			if _, err := os.Getwd(); err == nil {
				_ = os.Chdir(original)
				t.Fatal("Getwd() succeeded after current directory deletion")
			}
			runErr := tt.run()
			if err := os.Chdir(original); err != nil {
				t.Fatalf("restore original cwd: %v", err)
			}
			if runErr == nil || exitCodeForError(runErr) != ExitOperational {
				t.Fatalf("error = %v, want operational exit %d", runErr, ExitOperational)
			}
			message := strings.ToLower(runErr.Error())
			if !strings.Contains(message, "resolve path") && !strings.Contains(message, "working directory") && !strings.Contains(message, "getwd") {
				t.Fatalf("error = %q, want cwd/path resolution context", runErr)
			}
		})
	}
}
