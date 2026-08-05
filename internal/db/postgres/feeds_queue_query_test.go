package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEnqueueRefreshNoPositionUsesPositionlessHelper(t *testing.T) {
	t.Parallel()

	source := string(readFeedsQueueSource(t))

	direct := sourceBlock(t, source, "func (s *Store) EnqueueRefresh(ctx", "func (s *Store) EnqueueRefreshWithAudit")
	if !strings.Contains(direct, "s.enqueueRefresh(ctx, job, nil, true)") {
		t.Fatal("EnqueueRefresh must continue requesting a queue position")
	}

	audited := sourceBlock(t, source, "func (s *Store) EnqueueRefreshWithAudit", "func (s *Store) EnqueueRefreshNoPosition")
	if !strings.Contains(audited, "s.enqueueRefresh(ctx, job, audit, true)") {
		t.Fatal("EnqueueRefreshWithAudit must continue requesting a queue position for response/audit details")
	}

	positionless := sourceBlock(t, source, "func (s *Store) EnqueueRefreshNoPosition", "func (s *Store) enqueueRefresh")
	if !strings.Contains(positionless, "s.enqueueRefresh(ctx, job, nil, false)") {
		t.Fatal("EnqueueRefreshNoPosition must call enqueueRefresh with position counting disabled")
	}
	for _, forbidden := range []string{"queuePosition(", "COUNT(*)::int"} {
		if strings.Contains(positionless, forbidden) {
			t.Fatalf("EnqueueRefreshNoPosition block contains %q", forbidden)
		}
	}
}

func readFeedsQueueSource(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("feeds_queue.go")
	if err != nil {
		t.Fatalf("read feeds_queue.go: %v", err)
	}
	return data
}
