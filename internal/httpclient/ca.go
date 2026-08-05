package httpclient

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// LoadCAPool builds a certificate pool from a PEM bundle. An empty path returns
// nil so callers keep using the system trust store.
func LoadCAPool(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) // #nosec G304 -- user-specified CA bundle path
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no valid certificate", path)
	}
	return pool, nil
}
