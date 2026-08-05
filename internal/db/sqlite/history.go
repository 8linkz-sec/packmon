package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ScanEntry is a compact record of one scan stored in scan_history.
type ScanEntry struct {
	ID                int       `json:"id,omitempty"`
	RepoName          string    `json:"repo_name,omitempty"`
	Branch            string    `json:"branch,omitempty"`
	Commit            string    `json:"commit,omitempty"`
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
		INSERT INTO scan_history(repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, insert,
		entry.RepoName,
		entry.Branch,
		entry.Commit,
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
// combined. The number of deleted rows is returned.
func (s *Store) ClearHistory(ctx context.Context, before *time.Time, repo string) (int, error) {
	var (
		result sql.Result
		err    error
	)

	switch {
	case before != nil && repo != "":
		result, err = s.db.ExecContext(ctx,
			`DELETE FROM scan_history WHERE scanned_at < ? AND repo_name = ?`,
			before.UTC().Format(time.RFC3339),
			repo,
		)
	case before != nil:
		result, err = s.db.ExecContext(ctx,
			`DELETE FROM scan_history WHERE scanned_at < ?`,
			before.UTC().Format(time.RFC3339),
		)
	case repo != "":
		result, err = s.db.ExecContext(ctx,
			`DELETE FROM scan_history WHERE repo_name = ?`,
			repo,
		)
	default:
		result, err = s.db.ExecContext(ctx, `DELETE FROM scan_history`)
	}
	if err != nil {
		return 0, fmt.Errorf("sqlite: clear history: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: clear history rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

const scanHistoryRetentionVictimIDsQuery = `
	SELECT id
	FROM (
		SELECT id,
		       ROW_NUMBER() OVER (
			       PARTITION BY COALESCE(repo_name, '')
			       ORDER BY scanned_at DESC, id DESC
		       ) AS retained_rank
		FROM scan_history
	)
	WHERE retained_rank > ?`

const scanHistoryRetentionDeleteQuery = `
	DELETE FROM scan_history
	WHERE id IN (` + scanHistoryRetentionVictimIDsQuery + `
	)`

// EnforceRetention keeps at most maxPerRepo entries per repository,
// deleting the oldest entries beyond that limit. If maxPerRepo <= 0 the
// call is a no-op.
func (s *Store) EnforceRetention(ctx context.Context, maxPerRepo int) error {
	if maxPerRepo <= 0 {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, scanHistoryRetentionDeleteQuery, maxPerRepo); err != nil {
		return fmt.Errorf("sqlite: enforce history retention: %w", err)
	}

	return nil
}

// GetRecentScans returns the most recent scan entries, newest first. If
// repo is non-empty, only entries for that repository are returned.
// limit == 0 defaults to 50. limit < 0 returns all rows.
func (s *Store) GetRecentScans(ctx context.Context, repo string, limit int) ([]ScanEntry, error) {
	return s.getRecentScansPage(ctx, repo, limit, 0)
}

func (s *Store) getRecentScansPage(ctx context.Context, repo string, limit, offset int) ([]ScanEntry, error) {
	noLimit := limit < 0
	if limit == 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var query string
	var args []interface{}

	if repo != "" {
		query = `
			SELECT id, repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities
			FROM scan_history
			WHERE repo_name = ?
			ORDER BY scanned_at DESC`
		args = []interface{}{repo}
	} else {
		query = `
			SELECT id, repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities
			FROM scan_history
			ORDER BY scanned_at DESC`
	}
	if !noLimit {
		query += `
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query scan history: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var entries []ScanEntry
	for rows.Next() {
		var (
			entry        ScanEntry
			repoName     *string
			branch       *string
			commit       *string
			scannedAtStr string
			idsJSON      *string
			sevsJSON     *string
		)

		if err := rows.Scan(
			&entry.ID, &repoName, &branch, &commit, &scannedAtStr,
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
		if commit != nil {
			entry.Commit = *commit
		}

		parsedAt, err := time.Parse(time.RFC3339, scannedAtStr)
		if err != nil {
			return nil, fmt.Errorf("sqlite: decode scan history row %d scanned_at: %w", entry.ID, err)
		}
		entry.ScannedAt = parsedAt

		if idsJSON != nil && *idsJSON != "" {
			if err := json.Unmarshal([]byte(*idsJSON), &entry.FindingIDs); err != nil {
				return nil, fmt.Errorf("sqlite: decode scan history row %d finding_ids: %w", entry.ID, err)
			}
		}
		if sevsJSON != nil && *sevsJSON != "" {
			if err := json.Unmarshal([]byte(*sevsJSON), &entry.FindingSeverities); err != nil {
				return nil, fmt.Errorf("sqlite: decode scan history row %d finding_severities: %w", entry.ID, err)
			}
		}

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate scan history: %w", err)
	}

	return entries, nil
}
