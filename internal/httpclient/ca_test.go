package httpclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLoadCAPoolLoadsValidCertificate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	validAt := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Packmon test CA"},
		NotBefore:             validAt.Add(-time.Hour),
		NotAfter:              validAt.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated CA certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	pool, err := LoadCAPool(path)
	if err != nil {
		t.Fatalf("LoadCAPool() error = %v", err)
	}
	if pool == nil {
		t.Fatal("LoadCAPool() = nil, want certificate pool")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: validAt,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("generated CA is not trusted by loaded pool: %v", err)
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
