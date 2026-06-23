package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
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

func writeServerCertPEM(t *testing.T, server *httptest.Server, path string) {
	t.Helper()
	if server.TLS == nil || len(server.TLS.Certificates) == 0 {
		t.Fatal("test server has no TLS certificate")
	}
	var out []byte
	for _, cert := range server.TLS.Certificates {
		for _, der := range cert.Certificate {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
}

func reportHandlerError(w http.ResponseWriter, ch chan<- string, status int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	select {
	case ch <- msg:
	default:
	}
	http.Error(w, msg, status)
}

func assertNoHandlerError(t *testing.T, ch <-chan string) {
	t.Helper()

	select {
	case msg := <-ch:
		t.Fatal(msg)
	default:
	}
}
