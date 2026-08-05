package feed

import (
	"context"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
)

// DeleteVulnerabilityForSource requires source-scoped delete semantics. Feed
// syncers use this to withdraw their own source evidence without removing
// another feed's canonical advisory.
func DeleteVulnerabilityForSource(ctx context.Context, store db.Store, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("source-scoped vulnerability delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}
	if scoped, ok := store.(db.SourceVulnerabilityDeleter); ok {
		return scoped.DeleteVulnerabilityForSource(ctx, id, source)
	}
	return fmt.Errorf("source-scoped vulnerability delete unsupported by %T: %w", store, db.ErrSourceScopedDeleteUnsupported)
}

// DeleteMaliciousFindingForSource requires source-scoped delete semantics.
// Feed syncers use this to withdraw their own source evidence without removing
// another feed's malicious finding.
func DeleteMaliciousFindingForSource(ctx context.Context, store db.Store, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("source-scoped malicious finding delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}
	if scoped, ok := store.(db.SourceMaliciousFindingDeleter); ok {
		return scoped.DeleteMaliciousFindingForSource(ctx, id, source)
	}
	return fmt.Errorf("source-scoped malicious finding delete unsupported by %T: %w", store, db.ErrSourceScopedDeleteUnsupported)
}
