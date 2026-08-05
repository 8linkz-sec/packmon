package feed

import (
	"context"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type sourceDeleteLegacyStore struct {
	db.Store
	vulnerabilityID string
	maliciousID     string
}

func (s *sourceDeleteLegacyStore) DeleteVulnerability(_ context.Context, id string) error {
	s.vulnerabilityID = id
	return nil
}

func (s *sourceDeleteLegacyStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.maliciousID = id
	return nil
}

type sourceDeleteScopedStore struct {
	sourceDeleteLegacyStore
	vulnerabilitySource string
	maliciousSource     string
}

func (s *sourceDeleteScopedStore) DeleteVulnerabilityForSource(_ context.Context, id, source string) error {
	s.vulnerabilityID = id
	s.vulnerabilitySource = source
	return nil
}

func (s *sourceDeleteScopedStore) DeleteMaliciousFindingForSource(_ context.Context, id, source string) error {
	s.maliciousID = id
	s.maliciousSource = source
	return nil
}

func TestDeleteVulnerabilityForSourceUsesScopedStoreWhenAvailable(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteScopedStore{}
	if err := DeleteVulnerabilityForSource(context.Background(), store, "GHSA-1", "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource() error = %v", err)
	}
	if store.vulnerabilityID != "GHSA-1" || store.vulnerabilitySource != "osv" {
		t.Fatalf("scoped vulnerability delete = id %q source %q", store.vulnerabilityID, store.vulnerabilitySource)
	}
}

func TestDeleteVulnerabilityForSourceRequiresScopedStore(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteLegacyStore{}
	err := DeleteVulnerabilityForSource(context.Background(), store, "GHSA-2", "osv")
	if err == nil {
		t.Fatal("DeleteVulnerabilityForSource() error = nil, want unsupported")
	}
	if !strings.Contains(err.Error(), "source-scoped vulnerability delete unsupported") {
		t.Fatalf("DeleteVulnerabilityForSource() error = %v, want unsupported source-scoped delete", err)
	}
	if store.vulnerabilityID != "" {
		t.Fatalf("legacy vulnerability delete id = %q, want no whole-row fallback", store.vulnerabilityID)
	}
}

func TestDeleteVulnerabilityForSourceRejectsEmptySource(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteScopedStore{}
	err := DeleteVulnerabilityForSource(context.Background(), store, "GHSA-3", " ")
	if err == nil {
		t.Fatal("DeleteVulnerabilityForSource() error = nil, want unsupported")
	}
	if !strings.Contains(err.Error(), "source-scoped vulnerability delete requires source") {
		t.Fatalf("DeleteVulnerabilityForSource() error = %v, want source-required error", err)
	}
	if store.vulnerabilityID != "" || store.vulnerabilitySource != "" {
		t.Fatalf("scoped vulnerability delete = id %q source %q, want not called", store.vulnerabilityID, store.vulnerabilitySource)
	}
}

func TestDeleteMaliciousFindingForSourceUsesScopedStoreWhenAvailable(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteScopedStore{}
	if err := DeleteMaliciousFindingForSource(context.Background(), store, "MAL-1", "openssf"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource() error = %v", err)
	}
	if store.maliciousID != "MAL-1" || store.maliciousSource != "openssf" {
		t.Fatalf("scoped malicious delete = id %q source %q", store.maliciousID, store.maliciousSource)
	}
}

func TestDeleteMaliciousFindingForSourceRequiresScopedStore(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteLegacyStore{}
	err := DeleteMaliciousFindingForSource(context.Background(), store, "MAL-2", "openssf")
	if err == nil {
		t.Fatal("DeleteMaliciousFindingForSource() error = nil, want unsupported")
	}
	if !strings.Contains(err.Error(), "source-scoped malicious finding delete unsupported") {
		t.Fatalf("DeleteMaliciousFindingForSource() error = %v, want unsupported source-scoped delete", err)
	}
	if store.maliciousID != "" {
		t.Fatalf("legacy malicious delete id = %q, want no whole-row fallback", store.maliciousID)
	}
}

func TestDeleteMaliciousFindingForSourceRejectsEmptySource(t *testing.T) {
	t.Parallel()

	store := &sourceDeleteScopedStore{}
	err := DeleteMaliciousFindingForSource(context.Background(), store, "MAL-3", " ")
	if err == nil {
		t.Fatal("DeleteMaliciousFindingForSource() error = nil, want unsupported")
	}
	if !strings.Contains(err.Error(), "source-scoped malicious finding delete requires source") {
		t.Fatalf("DeleteMaliciousFindingForSource() error = %v, want source-required error", err)
	}
	if store.maliciousID != "" || store.maliciousSource != "" {
		t.Fatalf("scoped malicious delete = id %q source %q, want not called", store.maliciousID, store.maliciousSource)
	}
}
