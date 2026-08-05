package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// TestSkipSQLiteFilePermissionHardeningRecognisesNonFileTargets pins which paths
// carry no file to harden. Chmod on an in-memory or DSN-style path would fail
// and turn an otherwise healthy CLI start into an error.
func TestSkipSQLiteFilePermissionHardeningRecognisesNonFileTargets(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", "   ", ":memory:", "file:local.db?cache=shared"} {
		if !skipSQLiteFilePermissionHardening(path) {
			t.Errorf("skipSQLiteFilePermissionHardening(%q) = false, want it skipped", path)
		}
	}
	for _, path := range []string{"local.db", "/var/lib/packmon/local.db", `C:\packmon\local.db`} {
		if skipSQLiteFilePermissionHardening(path) {
			t.Errorf("skipSQLiteFilePermissionHardening(%q) = true, want a real file hardened", path)
		}
	}
}

// TestEnsurePrivateSQLiteDatabaseFileCreatesTheFile covers the pre-creation step
// that exists so the database file is owner-only from the moment it appears --
// creating it via the driver first would leave a window at the default umask.
func TestEnsurePrivateSQLiteDatabaseFileCreatesTheFile(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "local.db")
	if err := ensurePrivateSQLiteDatabaseFile(dbPath); err != nil {
		t.Fatalf("ensurePrivateSQLiteDatabaseFile: %v", err)
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
	// Windows does not implement POSIX permission bits, so only assert them
	// where the guarantee is real.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("permissions = %o, want 0600", perm)
		}
	}

	// Running again on an existing file must not fail or truncate it.
	if err := os.WriteFile(dbPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := ensurePrivateSQLiteDatabaseFile(dbPath); err != nil {
		t.Fatalf("second ensurePrivateSQLiteDatabaseFile: %v", err)
	}
	content, err := os.ReadFile(dbPath) // #nosec G304 -- test-controlled temp path.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(content) != "existing" {
		t.Fatalf("file content = %q, want the existing database left intact", content)
	}
}

// TestEnsurePrivateSQLiteDatabaseFileSkipsNonFileTargets keeps the in-memory and
// DSN paths from being turned into real files on disk.
func TestEnsurePrivateSQLiteDatabaseFileSkipsNonFileTargets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, path := range []string{":memory:", "file:" + filepath.Join(dir, "dsn.db")} {
		if err := ensurePrivateSQLiteDatabaseFile(path); err != nil {
			t.Fatalf("ensurePrivateSQLiteDatabaseFile(%q) = %v, want a no-op", path, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory holds %d entries, want the non-file targets to create nothing", len(entries))
	}
}

// TestChmodExistingSQLiteFileTreatsAMissingFileAsDone covers the WAL and shm
// side files: they only exist while the database is open, so their absence is
// normal and must not fail the hardening pass.
func TestChmodExistingSQLiteFileTreatsAMissingFileAsDone(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "never-created.db-wal")
	if err := chmodExistingSQLiteFile(missing, 0o600); err != nil {
		t.Fatalf("chmodExistingSQLiteFile(missing) = %v, want a silent success", err)
	}
}

// TestRestrictSQLiteFilePermissionsCoversTheSideFiles pins that the WAL and shm
// files are hardened too. They hold the same advisory data as the database, so
// hardening only the main file would leave it readable through the sidecars.
func TestRestrictSQLiteFilePermissionsCoversTheSideFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "local.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		// Deliberately world-readable: the point of the test is that the
		// hardening pass tightens an existing file, not that it was already tight.
		if err := os.WriteFile(dbPath+suffix, []byte("x"), 0o644); err != nil { // #nosec G306 -- fixture must start permissive to prove restrictSQLiteFilePermissions tightens it.
			t.Fatalf("seed %s: %v", dbPath+suffix, err)
		}
	}

	if err := restrictSQLiteFilePermissions(dbPath); err != nil {
		t.Fatalf("restrictSQLiteFilePermissions: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(dbPath + suffix)
		if err != nil {
			t.Fatalf("stat %s: %v", dbPath+suffix, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", dbPath+suffix, perm)
		}
	}
}

// TestValidateSyncResponseBeforeApplyRejectsUnusableResponses covers the gate the
// local sync runs before touching the database. An unparseable or empty full
// response must be refused, because applying it would replace good local data
// with nothing and then mark the database as freshly synced.
func TestValidateSyncResponseBeforeApplyRejectsUnusableResponses(t *testing.T) {
	t.Parallel()

	if err := validateSyncResponseBeforeApply(true, nil); err == nil {
		t.Error("a missing response was accepted")
	}
	if err := validateSyncResponseBeforeApply(false, &synccontract.Response{}); err == nil {
		t.Error("a response without synced_at was accepted")
	}
	if err := validateSyncResponseBeforeApply(false, &synccontract.Response{
		SyncedAt: "not-a-timestamp",
	}); err == nil {
		t.Error("an unparseable synced_at was accepted")
	}
	// A full sync that carries neither data nor feed state is the dangerous case.
	if err := validateSyncResponseBeforeApply(true, &synccontract.Response{
		SyncedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err == nil {
		t.Error("an empty full response was accepted")
	}
}

// TestValidateSyncResponseBeforeApplyAcceptsUsableResponses is the positive
// counterpart. An incremental sync legitimately carries no rows, and a full sync
// is usable as soon as it reports feed state even without advisory rows.
func TestValidateSyncResponseBeforeApplyAcceptsUsableResponses(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	if err := validateSyncResponseBeforeApply(false, &synccontract.Response{SyncedAt: now}); err != nil {
		t.Errorf("an empty incremental response was rejected: %v", err)
	}
	if err := validateSyncResponseBeforeApply(true, &synccontract.Response{
		SyncedAt:   now,
		FeedStatus: "healthy",
	}); err != nil {
		t.Errorf("a full response with feed status was rejected: %v", err)
	}
	if err := validateSyncResponseBeforeApply(true, &synccontract.Response{
		SyncedAt:     now,
		FeedVersions: map[string]string{"osv": "2026-08-04"},
	}); err != nil {
		t.Errorf("a full response with feed versions was rejected: %v", err)
	}
	if err := validateSyncResponseBeforeApply(true, &synccontract.Response{
		SyncedAt:        now,
		Vulnerabilities: []synccontract.Vulnerability{{ID: "GHSA-1"}},
	}); err != nil {
		t.Errorf("a full response carrying advisories was rejected: %v", err)
	}
}

// TestValidateLocalVersionRangesRejectsUnusableRanges covers the guard on stored
// version ranges. A range without events matches nothing, so accepting one would
// silently drop a vulnerability from every future local scan.
func TestValidateLocalVersionRangesRejectsUnusableRanges(t *testing.T) {
	t.Parallel()

	if err := validateLocalVersionRanges("GHSA-1", "version_ranges", `[{"events":[]}]`, false); err == nil {
		t.Error("a range with no events was accepted")
	} else if !strings.Contains(err.Error(), "GHSA-1") {
		t.Errorf("error = %v, want the finding ID named", err)
	}

	if err := validateLocalVersionRanges("GHSA-2", "version_ranges",
		`[{"events":[{"introduced":"  "}]}]`, false); err == nil {
		t.Error("an event with only blank bounds was accepted")
	}
	if err := validateLocalVersionRanges("GHSA-3", "version_ranges", `{"not":"an array"}`, false); err == nil {
		t.Error("a non-array payload was accepted")
	}
	if err := validateLocalVersionRanges("GHSA-4", "version_ranges", "null", false); err == nil {
		t.Error("a null payload was accepted where null is disallowed")
	}
}

// TestValidateLocalVersionRangesAcceptsEveryEventBound is the positive
// counterpart: each of the four bound kinds on its own makes an event usable.
func TestValidateLocalVersionRangesAcceptsEveryEventBound(t *testing.T) {
	t.Parallel()

	for _, bound := range []string{"introduced", "fixed", "last_affected", "limit"} {
		payload := `[{"events":[{"` + bound + `":"1.2.3"}]}]`
		if err := validateLocalVersionRanges("GHSA-1", "version_ranges", payload, false); err != nil {
			t.Errorf("bound %q was rejected: %v", bound, err)
		}
	}
	// An absent value is not a validation failure -- there is nothing to check.
	for _, empty := range []string{"", "   "} {
		if err := validateLocalVersionRanges("GHSA-1", "version_ranges", empty, false); err != nil {
			t.Errorf("empty payload %q was rejected: %v", empty, err)
		}
	}
	if err := validateLocalVersionRanges("GHSA-1", "version_ranges", "null", true); err != nil {
		t.Errorf("null was rejected although it is allowed here: %v", err)
	}
}

// TestRowsAffectedFallsBackToZero covers the helper used for sync delete counts.
// Not every driver reports affected rows, and a sync must not fail over a
// statistic -- it reports zero instead.
func TestRowsAffectedFallsBackToZero(t *testing.T) {
	t.Parallel()

	if got := rowsAffected(nil); got != 0 {
		t.Errorf("rowsAffected(nil) = %d, want 0", got)
	}
	if got := rowsAffected(unsupportedResult{}); got != 0 {
		t.Errorf("rowsAffected(unsupported driver) = %d, want 0", got)
	}
	if got := rowsAffected(countingResult{affected: 7}); got != 7 {
		t.Errorf("rowsAffected(7) = %d, want 7", got)
	}
}

type unsupportedResult struct{}

func (unsupportedResult) LastInsertId() (int64, error) { return 0, errUnsupportedResult }
func (unsupportedResult) RowsAffected() (int64, error) { return 0, errUnsupportedResult }

type countingResult struct{ affected int64 }

func (countingResult) LastInsertId() (int64, error)   { return 0, nil }
func (r countingResult) RowsAffected() (int64, error) { return r.affected, nil }

var errUnsupportedResult = errors.New("driver does not report affected rows")
