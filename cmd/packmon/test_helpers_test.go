package main

import (
	"path/filepath"
	"testing"

	"github.com/8linkz/packmon/internal/db/sqlite"
)

func isolateCLIConfigDiscovery(t *testing.T) {
	t.Helper()

	originalConfig := flagConfig
	originalLogLevel := flagLogLevel
	originalQuiet := flagQuiet
	originalNoColor := flagNoColor
	flagConfig = ""
	flagLogLevel = "INFO"
	flagQuiet = false
	flagNoColor = false
	t.Cleanup(func() {
		flagConfig = originalConfig
		flagLogLevel = originalLogLevel
		flagQuiet = originalQuiet
		flagNoColor = originalNoColor
	})

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())
}

func newTestSQLiteStore(t *testing.T, dbDir string) (*sqlite.Store, string) {
	t.Helper()

	path := filepath.Join(dbDir, "packmon.db")
	store, err := sqlite.New(path)
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store, path
}
