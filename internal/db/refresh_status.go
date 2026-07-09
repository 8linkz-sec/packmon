package db

import "strings"

const (
	RefreshStatusPending    = "pending"
	RefreshStatusProcessing = "processing"
	RefreshStatusPaused     = "paused"
	RefreshStatusDone       = "done"
	RefreshStatusError      = "error"
)

var (
	refreshStatuses          = []string{RefreshStatusPending, RefreshStatusProcessing, RefreshStatusPaused, RefreshStatusDone, RefreshStatusError}
	activeRefreshStatuses    = []string{RefreshStatusPending, RefreshStatusProcessing, RefreshStatusPaused}
	drainableRefreshStatuses = []string{RefreshStatusPending, RefreshStatusProcessing}
	terminalRefreshStatuses  = []string{RefreshStatusDone, RefreshStatusError}
	clearableRefreshStatuses = []string{RefreshStatusPending, RefreshStatusPaused, RefreshStatusDone, RefreshStatusError}
	retryableRefreshStatuses = []string{RefreshStatusDone, RefreshStatusError, RefreshStatusPaused}
)

func RefreshStatuses() []string {
	return cloneRefreshStatuses(refreshStatuses)
}

func ActiveRefreshStatuses() []string {
	return cloneRefreshStatuses(activeRefreshStatuses)
}

func DrainableRefreshStatuses() []string {
	return cloneRefreshStatuses(drainableRefreshStatuses)
}

// DrainableRefreshStatusPredicateSQL returns the literal refresh_queue status
// predicate that matches the queue drain partial index.
func DrainableRefreshStatusPredicateSQL() string {
	return refreshStatusPredicateSQL("status", drainableRefreshStatuses)
}

func TerminalRefreshStatuses() []string {
	return cloneRefreshStatuses(terminalRefreshStatuses)
}

func ClearableRefreshStatuses() []string {
	return cloneRefreshStatuses(clearableRefreshStatuses)
}

func RetryableRefreshStatuses() []string {
	return cloneRefreshStatuses(retryableRefreshStatuses)
}

func NormalizeRefreshStatus(raw string) (string, bool) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case RefreshStatusPending, RefreshStatusProcessing, RefreshStatusPaused, RefreshStatusDone, RefreshStatusError:
		return status, true
	default:
		return "", false
	}
}

func NormalizeClearableRefreshStatuses(statuses []string) []string {
	seen := make(map[string]struct{}, len(statuses))
	out := make([]string, 0, len(statuses))
	for _, raw := range statuses {
		status, ok := NormalizeRefreshStatus(raw)
		if !ok || !CanClearRefreshStatus(status) {
			continue
		}
		if _, ok := seen[status]; ok {
			continue
		}
		seen[status] = struct{}{}
		out = append(out, status)
	}
	return out
}

func IsActiveRefreshStatus(status string) bool {
	status, ok := NormalizeRefreshStatus(status)
	return ok && (status == RefreshStatusPending || status == RefreshStatusProcessing || status == RefreshStatusPaused)
}

func IsDrainableRefreshStatus(status string) bool {
	status, ok := NormalizeRefreshStatus(status)
	return ok && (status == RefreshStatusPending || status == RefreshStatusProcessing)
}

func IsTerminalRefreshStatus(status string) bool {
	status, ok := NormalizeRefreshStatus(status)
	return ok && (status == RefreshStatusDone || status == RefreshStatusError)
}

func CanClearRefreshStatus(status string) bool {
	status, ok := NormalizeRefreshStatus(status)
	return ok && (status == RefreshStatusPending || status == RefreshStatusPaused || IsTerminalRefreshStatus(status))
}

func CanRetryRefreshStatus(status string) bool {
	status, ok := NormalizeRefreshStatus(status)
	return ok && (status == RefreshStatusDone || status == RefreshStatusError || status == RefreshStatusPaused)
}

func RefreshStatusLabel(status string) string {
	raw := strings.TrimSpace(status)
	status, ok := NormalizeRefreshStatus(status)
	if !ok {
		return raw
	}
	switch status {
	case RefreshStatusPending:
		return "Pending"
	case RefreshStatusProcessing:
		return "Processing"
	case RefreshStatusPaused:
		return "Paused"
	case RefreshStatusDone:
		return "Done"
	case RefreshStatusError:
		return "Error"
	default:
		return status
	}
}

func cloneRefreshStatuses(statuses []string) []string {
	return append([]string(nil), statuses...)
}

func refreshStatusPredicateSQL(column string, statuses []string) string {
	quoted := make([]string, 0, len(statuses))
	for _, status := range statuses {
		quoted = append(quoted, "'"+status+"'")
	}
	return column + " IN (" + strings.Join(quoted, ", ") + ")"
}
