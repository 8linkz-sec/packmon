package v1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/synccontract"
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

const (
	// syncMaxOffset bounds legacy offset pagination. Modern clients should use
	// the keyset cursor fields returned in next_cursor.
	syncMaxOffset = 10000

	// syncMaxXID bounds XID cursors to PostgreSQL signed bigint comparisons.
	syncMaxXID = math.MaxInt64

	maxSyncAuditDetailValueLength = 128
)

type syncResponsePayload = synccontract.Response

func parseSyncCursor(r *http.Request) (db.SyncCursor, error) {
	var cursor db.SyncCursor
	query := r.URL.Query()
	params := []struct {
		name   string
		target *int
	}{
		{name: "vulnerabilities_offset", target: &cursor.Vulnerabilities},
		{name: "malicious_offset", target: &cursor.Malicious},
		{name: "reputation_offset", target: &cursor.Reputation},
		{name: "lifecycle_offset", target: &cursor.Lifecycle},
	}
	for _, param := range params {
		raw := strings.TrimSpace(query.Get(param.name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > syncMaxOffset {
			return db.SyncCursor{}, fmt.Errorf("invalid %s parameter", param.name)
		}
		*param.target = parsed
	}

	cursorParams := []struct {
		name   string
		target *string
		parts  int
	}{
		{name: "vulnerabilities_cursor", target: &cursor.VulnerabilitiesCursor, parts: 3},
		{name: "malicious_cursor", target: &cursor.MaliciousCursor, parts: 3},
		{name: "reputation_cursor", target: &cursor.ReputationCursor, parts: 3},
		{name: "lifecycle_cursor", target: &cursor.LifecycleCursor, parts: 4},
	}
	for _, param := range cursorParams {
		raw := strings.TrimSpace(query.Get(param.name))
		if raw == "" {
			continue
		}
		if err := validateSyncCursorKey(raw, param.parts); err != nil {
			return db.SyncCursor{}, fmt.Errorf("invalid %s parameter", param.name)
		}
		*param.target = raw
	}

	doneParams := []struct {
		name   string
		target *bool
	}{
		{name: "vulnerabilities_done", target: &cursor.VulnerabilitiesDone},
		{name: "malicious_done", target: &cursor.MaliciousDone},
		{name: "reputation_done", target: &cursor.ReputationDone},
		{name: "lifecycle_done", target: &cursor.LifecycleDone},
	}
	for _, param := range doneParams {
		raw := strings.TrimSpace(query.Get(param.name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return db.SyncCursor{}, fmt.Errorf("invalid %s parameter", param.name)
		}
		*param.target = parsed
	}
	return cursor, nil
}

func validateSyncCursorKey(raw string, wantParts int) error {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	var values []string
	if err := json.Unmarshal(payload, &values); err != nil {
		return err
	}
	if len(values) != wantParts {
		return fmt.Errorf("cursor has %d parts, want %d", len(values), wantParts)
	}
	return nil
}

func parseOptionalUintQuery(r *http.Request, name string) (uint64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || parsed > syncMaxXID {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	return parsed, nil
}

func parseSyncExportOptions(r *http.Request) (db.SyncExportOptions, error) {
	var sincePtr *time.Time
	sinceRaw := strings.TrimSpace(r.URL.Query().Get("since"))
	if sinceRaw != "" {
		since, err := parseRFC3339Timestamp(sinceRaw)
		if err != nil {
			return db.SyncExportOptions{}, errors.New("invalid since timestamp")
		}
		sincePtr = &since
	}

	var snapshot time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("snapshot")); raw != "" {
		parsed, err := parseRFC3339Timestamp(raw)
		if err != nil {
			return db.SyncExportOptions{}, errors.New("invalid snapshot parameter")
		}
		snapshot = parsed.UTC()
	}
	sinceXID, err := parseOptionalUintQuery(r, "since_xid")
	if err != nil {
		return db.SyncExportOptions{}, err
	}
	snapshotXID, err := parseOptionalUintQuery(r, "snapshot_xid")
	if err != nil {
		return db.SyncExportOptions{}, err
	}

	limit := synccontract.DefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > synccontract.MaxLimit {
			return db.SyncExportOptions{}, errors.New("invalid limit parameter")
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > syncMaxOffset {
			return db.SyncExportOptions{}, errors.New("invalid offset parameter")
		}
		offset = parsed
	}
	cursor, err := parseSyncCursor(r)
	if err != nil {
		return db.SyncExportOptions{}, err
	}
	ecosystems, err := parseSyncEcosystems(r.URL.Query().Get("ecosystem"))
	if err != nil {
		return db.SyncExportOptions{}, err
	}

	return db.SyncExportOptions{
		Since:       sincePtr,
		SinceXID:    sinceXID,
		SnapshotAt:  snapshot,
		SnapshotXID: snapshotXID,
		Ecosystems:  ecosystems,
		Limit:       limit,
		Offset:      offset,
		Cursor:      cursor,
	}, nil
}

type syncRequest struct {
	options       db.SyncExportOptions
	correlationID string
}

type syncExportFailure struct {
	logMessage      string
	responseMessage string
	attrs           []any
}

func parseSyncRequest(r *http.Request) (syncRequest, error) {
	opts, err := parseSyncExportOptions(r)
	if err != nil {
		return syncRequest{}, err
	}
	return syncRequest{
		options:       opts,
		correlationID: requestCorrelationID(r),
	}, nil
}

func (h *Handler) HandleSync(w http.ResponseWriter, r *http.Request) {
	r = requestWithLogger(r, h.logger)
	if !isGetOrHead(r.Method) {
		methodNotAllowedForRequest(w, r, http.MethodGet, http.MethodHead)
		return
	}

	syncReq, err := parseSyncRequest(r)
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if r.Method == http.MethodHead {
		writeJSONHead(w, http.StatusOK)
		return
	}

	exported, failure := h.exportSyncData(r, syncReq)
	if failure != nil {
		h.logger.Error(failure.logMessage, failure.attrs...)
		errorResponseForRequest(w, r, http.StatusInternalServerError, failure.responseMessage)
		return
	}

	resp := h.syncResponseEnvelope(r.Context(), exported, syncReq.correlationID)
	writeStreamingJSONForRequest(w, r, http.StatusOK, resp)
}

func (h *Handler) exportSyncData(r *http.Request, req syncRequest) (*db.SyncExport, *syncExportFailure) {
	if err := h.auditSyncExportAttempt(r, req.options, req.correlationID); err != nil {
		return nil, &syncExportFailure{
			logMessage:      "sync export audit failed",
			responseMessage: "failed to audit sync export",
			attrs:           syncExportLogAttrs(r, req.correlationID, err),
		}
	}

	exported, err := h.store.ExportSync(r.Context(), req.options)
	if err != nil {
		return nil, &syncExportFailure{
			logMessage:      "sync export failed",
			responseMessage: "failed to export sync data",
			attrs:           []any{"error", err, "correlation_id", req.correlationID},
		}
	}
	return exported, nil
}

func (h *Handler) syncResponseEnvelope(ctx context.Context, exported *db.SyncExport, correlationID string) syncResponsePayload {
	feedStatus, feedVersions := h.feedState(ctx, correlationID)
	if feedStatus == string(domain.ScanFeedStatusDegraded) {
		telemetry.Default().IncDegradedResponses()
	}
	return syncResponseFromExport(exported, feedStatus, feedVersions)
}

func syncResponseFromExport(exported *db.SyncExport, feedStatus string, feedVersions map[string]string) syncResponsePayload {
	resp := newSyncResponseEnvelope(exported, feedStatus, feedVersions)
	if exported == nil {
		return resp
	}
	resp.Vulnerabilities = syncVulnerabilityResponses(exported.Vulnerabilities)
	resp.Malicious = syncMaliciousResponses(exported.Malicious)
	resp.Reputation = syncReputationResponses(exported.Reputation)
	resp.Lifecycle = syncLifecycleResponses(exported.Lifecycle)
	return resp
}

func newSyncResponseEnvelope(exported *db.SyncExport, feedStatus string, feedVersions map[string]string) syncResponsePayload {
	resp := syncResponsePayload{
		FeedStatus:      feedStatus,
		FeedVersions:    feedVersions,
		Vulnerabilities: []synccontract.Vulnerability{},
		Malicious:       []synccontract.Malicious{},
		Reputation:      []synccontract.Reputation{},
		Lifecycle:       []synccontract.Lifecycle{},
	}
	if exported == nil {
		return resp
	}
	resp.SyncedAt = formatAPIDateTime(exported.SyncedAt)
	resp.SyncedXID = exported.SyncedXID
	resp.Truncated = exported.Truncated
	resp.HasMore = exported.Truncated
	resp.NextCursor = syncCursorResponse(exported.NextCursor)
	return resp
}

func syncVulnerabilityResponses(items []db.SyncVulnerability) []synccontract.Vulnerability {
	out := make([]synccontract.Vulnerability, 0, len(items))
	for _, item := range items {
		out = append(out, synccontract.Vulnerability{
			ID:               item.ID,
			Ecosystem:        item.Ecosystem,
			Name:             item.Name,
			VersionRanges:    item.VersionRanges,
			VersionsAffected: item.VersionsAffected,
			References:       item.References,
			Severity:         item.Severity,
			CVSSScore:        item.CVSSScore,
			EPSSScore:        item.EPSSScore,
			EPSSPercentile:   item.EPSSPercentile,
			CISAKEV:          item.CISAKEV,
			Summary:          item.Summary,
			Source:           item.Source,
			Withdrawn:        item.Withdrawn,
		})
	}
	return out
}

func syncMaliciousResponses(items []db.SyncMalicious) []synccontract.Malicious {
	out := make([]synccontract.Malicious, 0, len(items))
	for _, item := range items {
		out = append(out, synccontract.Malicious{
			ID:            item.ID,
			Ecosystem:     item.Ecosystem,
			Name:          item.Name,
			VersionRanges: item.VersionRanges,
			Versions:      item.Versions,
			ReferenceURLs: item.ReferenceURLs,
			RiskType:      item.RiskType,
			Severity:      item.Severity,
			Summary:       item.Summary,
			Source:        item.Source,
			Withdrawn:     item.Withdrawn,
		})
	}
	return out
}

func syncReputationResponses(items []db.SyncReputationFinding) []synccontract.Reputation {
	out := make([]synccontract.Reputation, 0, len(items))
	for _, item := range items {
		out = append(out, synccontract.Reputation{
			ID:        item.ID,
			Ecosystem: item.Ecosystem,
			Name:      item.Name,
			Version:   item.Version,
			Type:      item.Type,
			RiskType:  item.RiskType,
			Severity:  item.Severity,
			Summary:   item.Summary,
			Withdrawn: item.Withdrawn,
		})
	}
	return out
}

func syncLifecycleResponses(items []db.SyncLifecycleRelease) []synccontract.Lifecycle {
	out := make([]synccontract.Lifecycle, 0, len(items))
	for _, item := range items {
		out = append(out, synccontract.Lifecycle{
			ID:               item.ID,
			Ecosystem:        item.Ecosystem,
			Name:             item.Name,
			ProductSlug:      item.ProductSlug,
			ProductLabel:     item.ProductLabel,
			Cycle:            item.Cycle,
			Latest:           item.Latest,
			ReleaseDate:      syncDateOnly(item.ReleaseDate),
			IsLTS:            item.IsLTS,
			LTSFrom:          syncDateOnly(item.LTSFrom),
			IsEOAS:           item.IsEOAS,
			EOASFrom:         syncDateOnly(item.EOASFrom),
			IsEOL:            item.IsEOL,
			EOLFrom:          syncDateOnly(item.EOLFrom),
			IsDiscontinued:   item.IsDiscontinued,
			DiscontinuedFrom: syncDateOnly(item.DiscontinuedFrom),
			IsEOES:           item.IsEOES,
			EOESFrom:         syncDateOnly(item.EOESFrom),
			IsMaintained:     item.IsMaintained,
			Withdrawn:        item.Withdrawn,
		})
	}
	return out
}

func syncCursorResponse(cursor *db.SyncCursor) *synccontract.Cursor {
	if cursor == nil {
		return nil
	}
	return &synccontract.Cursor{
		Vulnerabilities:       cursor.Vulnerabilities,
		Malicious:             cursor.Malicious,
		Reputation:            cursor.Reputation,
		Lifecycle:             cursor.Lifecycle,
		VulnerabilitiesCursor: cursor.VulnerabilitiesCursor,
		MaliciousCursor:       cursor.MaliciousCursor,
		ReputationCursor:      cursor.ReputationCursor,
		LifecycleCursor:       cursor.LifecycleCursor,
		VulnerabilitiesDone:   cursor.VulnerabilitiesDone,
		MaliciousDone:         cursor.MaliciousDone,
		ReputationDone:        cursor.ReputationDone,
		LifecycleDone:         cursor.LifecycleDone,
	}
}

func syncDateOnly(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.DateOnly)
	return &formatted
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseSyncEcosystems(raw string) ([]string, error) {
	ecosystems := splitCSV(raw)
	for i, ecosystem := range ecosystems {
		normalized := strings.ToLower(ecosystem)
		if !domain.Ecosystem(normalized).Valid() {
			return nil, fmt.Errorf("invalid ecosystem filter: %s", ecosystem)
		}
		ecosystems[i] = normalized
	}
	return ecosystems, nil
}

func (h *Handler) auditSyncExportAttempt(r *http.Request, opts db.SyncExportOptions, correlationID string) error {
	details, err := syncExportAuditDetails(r, opts, correlationID)
	if err != nil {
		return fmt.Errorf("build sync export audit details: %w", err)
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), scanLogInsertTimeout)
	defer cancel()
	if err := h.store.InsertAdminAuditLog(auditCtx, &db.AdminAuditEntry{
		Action:  "sync_export",
		Details: details,
		IP:      clientIP(r),
	}); err != nil {
		return fmt.Errorf("insert sync export audit: %w", err)
	}
	return nil
}

func syncExportAuditDetails(r *http.Request, opts db.SyncExportOptions, correlationID string) (json.RawMessage, error) {
	details := map[string]any{
		"method":         r.Method,
		"limit":          opts.Limit,
		"correlation_id": logsafe.BoundedDiagnosticValue(correlationID, maxSyncAuditDetailValueLength),
	}
	if opts.Since != nil {
		details["since"] = formatAPIDateTime(*opts.Since)
	}
	if opts.SinceXID > 0 {
		details["since_xid"] = opts.SinceXID
	}
	if !opts.SnapshotAt.IsZero() {
		details["snapshot"] = formatAPIDateTime(opts.SnapshotAt)
	}
	if opts.SnapshotXID > 0 {
		details["snapshot_xid"] = opts.SnapshotXID
	}
	if len(opts.Ecosystems) > 0 {
		details["ecosystems"] = append([]string(nil), opts.Ecosystems...)
	}
	if opts.Offset > 0 {
		details["offset"] = opts.Offset
	}
	addSyncCursorAuditDetails(details, opts.Cursor)
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		details["api_key_id"] = identity.ID
		details["api_key_name"] = logsafe.BoundedDiagnosticValue(identity.Name, maxSyncAuditDetailValueLength)
	}
	return json.Marshal(details)
}

func syncExportLogAttrs(r *http.Request, correlationID string, err error) []any {
	attrs := []any{
		"error", err,
		"correlation_id", logsafe.BoundedDiagnosticValue(correlationID, maxSyncAuditDetailValueLength),
		"client_ip", clientIP(r),
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		attrs = append(attrs,
			"api_key_id", identity.ID,
			"api_key_name", logsafe.BoundedDiagnosticValue(identity.Name, maxSyncAuditDetailValueLength),
		)
	}
	return attrs
}

func addSyncCursorAuditDetails(details map[string]any, cursor db.SyncCursor) {
	if cursor.Vulnerabilities > 0 {
		details["vulnerabilities_offset"] = cursor.Vulnerabilities
	}
	if cursor.Malicious > 0 {
		details["malicious_offset"] = cursor.Malicious
	}
	if cursor.Reputation > 0 {
		details["reputation_offset"] = cursor.Reputation
	}
	if cursor.Lifecycle > 0 {
		details["lifecycle_offset"] = cursor.Lifecycle
	}
	if cursor.VulnerabilitiesCursor != "" {
		details["vulnerabilities_cursor_provided"] = true
	}
	if cursor.MaliciousCursor != "" {
		details["malicious_cursor_provided"] = true
	}
	if cursor.ReputationCursor != "" {
		details["reputation_cursor_provided"] = true
	}
	if cursor.LifecycleCursor != "" {
		details["lifecycle_cursor_provided"] = true
	}
	if cursor.VulnerabilitiesDone {
		details["vulnerabilities_done"] = true
	}
	if cursor.MaliciousDone {
		details["malicious_done"] = true
	}
	if cursor.ReputationDone {
		details["reputation_done"] = true
	}
	if cursor.LifecycleDone {
		details["lifecycle_done"] = true
	}
}

func parseRFC3339Timestamp(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp")
}
