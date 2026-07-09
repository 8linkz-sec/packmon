package devstore

import (
	"context"
	"sync"

	"github.com/8linkz-sec/packmon/internal/db"
)

// Store satisfies db.Store using in-memory data structures. It is used during
// development when no PostgreSQL instance is available so that local web and
// admin flows remain usable without external services.
type Store struct {
	mu sync.Mutex

	adminAuth     *db.AdminAuth
	apiKeys       []db.APIKey
	auditLog      []db.AdminAuditLogEntry
	feedConfigs   map[string]db.FeedConfig
	feedStatuses  map[string]db.FeedSyncStatus
	systemConfig  *db.SystemSettings
	vulnerable    map[string]db.Vulnerability
	malicious     map[string]db.MaliciousFinding
	maliciousDel  map[string]db.SyncMalicious
	checkStatuses map[string]db.PackageCheckStatus
	scanLogs      []db.ScanLogEntry
	refreshJobs   []db.RefreshJob
	nextAPIKeyID  int
	nextAuditID   int
	nextManualID  int
	nextJobID     int
}

var _ db.Store = (*Store)(nil)

// NewStore creates an empty in-memory development store.
func NewStore() *Store {
	return &Store{
		feedConfigs:   make(map[string]db.FeedConfig),
		feedStatuses:  make(map[string]db.FeedSyncStatus),
		vulnerable:    make(map[string]db.Vulnerability),
		malicious:     make(map[string]db.MaliciousFinding),
		maliciousDel:  make(map[string]db.SyncMalicious),
		checkStatuses: make(map[string]db.PackageCheckStatus),
	}
}

type noopStore = Store

func newNoopStore() *Store { return NewStore() }

func (*Store) Close() error { return nil }

func (*Store) DBPoolStats() db.DBPoolStats { return db.DBPoolStats{} }

// Pinger satisfies health.Pinger and always succeeds.
type Pinger struct{}

type noopPinger = Pinger

func (*Pinger) Ping(context.Context) error { return nil }
