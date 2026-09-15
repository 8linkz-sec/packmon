package httpclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCAPoolEmptyPathUsesSystemTrust(t *testing.T) {
	pool, err := LoadCAPool(" \t ")
	if err != nil {
		t.Fatalf("LoadCAPool() error = %v", err)
	}
	if pool != nil {
		t.Fatalf("LoadCAPool() = %#v, want nil", pool)
	}
}

func TestLoadCAPoolRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCAPool(path)
	if err == nil || !strings.Contains(err.Error(), "contains no valid certificate") {
		t.Fatalf("LoadCAPool() error = %v, want invalid certificate error", err)
	}
}

func TestLoadCAPoolWrapsUnreadableBundle(t *testing.T) {
	_, err := LoadCAPool(filepath.Join(t.TempDir(), "missing-ca.pem"))
	if err == nil {
		t.Fatal("LoadCAPool() error = nil, want read error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadCAPool() error = %v, want wrapped fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "read CA bundle") {
		t.Fatalf("LoadCAPool() error = %v, want CA bundle context", err)
	}
}
