package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ScanEntry is a compact record of one scan stored in scan_history.
type ScanEntry struct {
	ID                int       `json:"id,omitempty"`
	RepoName          string    `json:"repo_name,omitempty"`
	Branch            string    `json:"branch,omitempty"`
	ScannedAt         time.Time `json:"scanned_at"`
	PackagesCount     int       `json:"packages_count"`
	FindingsCount     int       `json:"findings_count"`
	FindingIDs        []string  `json:"finding_ids,omitempty"`
	FindingSeverities []string  `json:"finding_severities,omitempty"`
}

// InsertScan stores a compact scan summary in the local history table.
func (s *Store) InsertScan(ctx context.Context, entry ScanEntry) error {
	idsJSON, err := json.Marshal(entry.FindingIDs)
	if err != nil {
		return fmt.Errorf("sqlite: marshal finding_ids: %w", err)
	}
	sevsJSON, err := json.Marshal(entry.FindingSeverities)
	if err != nil {
		return fmt.Errorf("sqlite: marshal finding_severities: %w", err)
	}

	const insert = `
		INSERT INTO scan_history(repo_name, branch, scanned_at, packages_count, findings_count, finding_ids, finding_severities)
		VALUES(?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, insert,
		entry.RepoName,
		entry.Branch,
		entry.ScannedAt.UTC().Format(time.RFC3339),
		entry.PackagesCount,
		entry.FindingsCount,
		string(idsJSON),
		string(sevsJSON),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert scan history: %w", err)
	}

	return nil
}

// ClearHistory deletes scan history entries. If before is non-nil, only
// entries older than that timestamp are deleted. If repo is non-empty,
// only entries for that repository are deleted. Both filters can be
// combined.
func (s *Store) ClearHistory(ctx context.Context, before *time.Time, repo string) error {
	var conditions []string
	var args []interface{}

	if before != nil {
		conditions = append(conditions, "scanned_at < ?")
		args = append(args, before.UTC().Format(time.RFC3339))
	}
	if repo != "" {
		conditions = append(conditions, "repo_name = ?")
		args = append(args, repo)
	}

	query := "DELETE FROM scan_history"
	if len(conditions) > 0 {
		query += " WHERE " + joinAnd(conditions)
	}

	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("sqlite: clear history: %w", err)
	}
	return nil
}

// EnforceRetention keeps at most maxPerRepo entries per repository,
// deleting the oldest entries beyond that limit. If maxPerRepo <= 0 the
// call is a no-op.
func (s *Store) EnforceRetention(ctx context.Context, maxPerRepo int) error {
	if maxPerRepo <= 0 {
		return nil
	}

	// Find distinct repo names (including empty string for anonymous scans).
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT COALESCE(repo_name, '') FROM scan_history`)
	if err != nil {
		return fmt.Errorf("sqlite: list repos for retention: %w", err)
	}
	defer rows.Close()

	var repos []string
	for rows.Next() {
		var repo string
		if err := rows.Scan(&repo); err != nil {
			return fmt.Errorf("sqlite: scan repo name: %w", err)
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate repo names: %w", err)
	}

	// For each repo, delete excess rows beyond the retention limit.
	const deleteExcess = `
		DELETE FROM scan_history
		WHERE id NOT IN (
			SELECT id FROM scan_history
			WHERE COALESCE(repo_name, '') = ?
			ORDER BY scanned_at DESC
			LIMIT ?
		) AND COALESCE(repo_name, '') = ?`

	for _, repo := range repos {
		if _, err := s.db.ExecContext(ctx, deleteExcess, repo, maxPerRepo, repo); err != nil {
			return fmt.Errorf("sqlite: enforce retention for repo %q: %w", repo, err)
		}
	}

	return nil
}

// GetRecentScans returns the most recent scan entries, newest first. If
// repo is non-empty, only entries for that repository are returned.
// limit <= 0 defaults to 50.
func (s *Store) GetRecentScans(ctx context.Context, repo string, limit int) ([]ScanEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	var query string
	var args []interface{}

	if repo != "" {
		query = `
			SELECT id, repo_name, branch, scanned_at, packages_count, findings_count, finding_ids, finding_severities
			FROM scan_history
			WHERE repo_name = ?
			ORDER BY scanned_at DESC
			LIMIT ?`
		args = []interface{}{repo, limit}
	} else {
		query = `
			SELECT id, repo_name, branch, scanned_at, packages_count, findings_count, finding_ids, finding_severities
			FROM scan_history
			ORDER BY scanned_at DESC
			LIMIT ?`
		args = []interface{}{limit}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query scan history: %w", err)
	}
	defer rows.Close()

	var entries []ScanEntry
	for rows.Next() {
		var (
			entry        ScanEntry
			repoName     *string
			branch       *string
			scannedAtStr string
			idsJSON      *string
			sevsJSON     *string
		)

		if err := rows.Scan(
			&entry.ID, &repoName, &branch, &scannedAtStr,
			&entry.PackagesCount, &entry.FindingsCount,
			&idsJSON, &sevsJSON,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan history row: %w", err)
		}

		if repoName != nil {
			entry.RepoName = *repoName
		}
		if branch != nil {
			entry.Branch = *branch
		}

		entry.ScannedAt, _ = time.Parse(time.RFC3339, scannedAtStr)

		if idsJSON != nil && *idsJSON != "" {
			_ = json.Unmarshal([]byte(*idsJSON), &entry.FindingIDs)
		}
		if sevsJSON != nil && *sevsJSON != "" {
			_ = json.Unmarshal([]byte(*sevsJSON), &entry.FindingSeverities)
		}

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate scan history: %w", err)
	}

	return entries, nil
}

// joinAnd joins SQL conditions with " AND ".
func joinAnd(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " AND "
		}
		result += p
	}
	return result
}
