package postgres

import (
	"context"
	"fmt"
)

// RemovePacketStormReferences deletes stored vulnerability references for
// Packet Storm URLs. Those links currently redirect to Terms of Service pages
// instead of the underlying report, so they are not useful as user-facing
// advisory resources.
func (s *Store) RemovePacketStormReferences(ctx context.Context) (int, error) {
	const query = `
		WITH deleted AS (
			DELETE FROM vulnerability_references
			WHERE lower(url) LIKE '%packetstormsecurity.com%'
			   OR lower(url) LIKE '%packetstorm.news%'
			RETURNING 1
		)
		SELECT COUNT(*) FROM deleted`

	var removed int
	if err := s.pool.QueryRow(ctx, query).Scan(&removed); err != nil {
		return 0, fmt.Errorf("postgres: remove Packet Storm references: %w", err)
	}
	return removed, nil
}
