package endoflife

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
	lifecyclemaps "github.com/8linkz-sec/packmon/internal/lifecycle"
	"github.com/8linkz-sec/packmon/internal/sbom"
)

const (
	FeedName        = "endoflife"
	lifecycleSource = "endoflife.date"
)

var _ feed.FeedSyncer = (*Syncer)(nil)

type Syncer struct {
	logger *slog.Logger
	client *Client
}

type Option func(*Syncer)

func WithBaseURL(baseURL string) Option {
	return func(s *Syncer) {
		s.client.BaseURL = baseURL
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(s *Syncer) {
		s.client.HTTPClient = client
	}
}

func WithUserAgent(userAgent string) Option {
	return func(s *Syncer) {
		s.client.UserAgent = userAgent
	}
}

func NewSyncer(logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	syncer := &Syncer{
		logger: logger.With(slog.String("feed", FeedName)),
		client: &Client{},
	}
	for _, opt := range opts {
		opt(syncer)
	}
	return syncer
}

func (s *Syncer) Name() string { return FeedName }

func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now()
	status := s.loadStatus(ctx, store)
	storedETag := statusETag(status)

	resp, etag, notModified, err := s.client.FetchProductsFull(ctx, storedETag)
	if err != nil {
		s.recordSyncFailure(ctx, store, start, err)
		return nil, err
	}
	if notModified {
		if etag == "" {
			etag = storedETag
		}
		synced, total := statusCounts(status)
		s.recordSyncSuccess(ctx, store, start, total, synced, etag, syncMetadata{ETag: etag})
		return &feed.SyncResult{EntriesSynced: synced, EntriesTotal: total}, nil
	}

	products := make([]db.LifecycleProduct, 0, len(resp.Result))
	for _, product := range resp.Result {
		mapped, err := mapProduct(product)
		if err != nil {
			syncErr := feed.NonRetryableError(fmt.Errorf("map lifecycle product: %w", err))
			s.recordSyncFailure(ctx, store, start, syncErr)
			return nil, syncErr
		}
		products = append(products, mapped)
	}

	deletedProducts, err := store.ReplaceLifecycleProducts(ctx, products)
	if err != nil {
		s.recordSyncFailure(ctx, store, start, err)
		return nil, fmt.Errorf("replace lifecycle products: %w", err)
	}

	total := resp.Total
	if total == 0 {
		total = len(resp.Result)
	}
	metadata := syncMetadata{
		ETag:            etag,
		SchemaVersion:   resp.SchemaVersion,
		GeneratedAt:     resp.GeneratedAt,
		DeletedProducts: deletedProducts,
	}
	s.logger.Info("completed endoflife lifecycle product reconciliation",
		slog.Int("products", len(products)),
		slog.Int("deleted_products", deletedProducts))
	s.recordSyncSuccess(ctx, store, start, total, len(products), etag, metadata)
	return &feed.SyncResult{EntriesSynced: len(products), EntriesTotal: total}, nil
}

type syncMetadata struct {
	ETag            string `json:"etag,omitempty"`
	SchemaVersion   string `json:"schema_version,omitempty"`
	GeneratedAt     string `json:"generated_at,omitempty"`
	DeletedProducts int    `json:"deleted_products,omitempty"`
}

func (s *Syncer) loadStatus(ctx context.Context, store db.Store) *db.FeedSyncStatus {
	status, err := store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil {
		s.logger.Warn("failed to load endoflife feed status", "error", err)
		return nil
	}
	return status
}

func statusETag(status *db.FeedSyncStatus) string {
	if status == nil {
		return ""
	}
	if strings.TrimSpace(status.LastETag) != "" {
		return strings.TrimSpace(status.LastETag)
	}
	if len(status.Metadata) == 0 {
		return ""
	}
	var metadata syncMetadata
	if err := json.Unmarshal(status.Metadata, &metadata); err != nil {
		return ""
	}
	return strings.TrimSpace(metadata.ETag)
}

func statusCounts(status *db.FeedSyncStatus) (synced, total int) {
	if status == nil {
		return 0, 0
	}
	return status.EntriesSynced, status.EntriesTotal
}

func (s *Syncer) recordSyncSuccess(ctx context.Context, store db.Store, start time.Time, total, synced int, etag string, metadata syncMetadata) {
	duration := time.Since(start)
	now := time.Now().UTC()
	if metadata.ETag == "" {
		metadata.ETag = etag
	}
	metadataJSON, _ := json.Marshal(metadata)
	if err := feed.UpsertFeedSyncStatusBounded(store, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   db.FeedSyncStatusSuccess,
		EntriesSynced:    synced,
		EntriesTotal:     total,
		LastETag:         etag,
		Metadata:         metadataJSON,
	}); err != nil {
		s.logger.Warn("failed to record endoflife sync success", "error", err)
	}
	_ = ctx
}

func (s *Syncer) recordSyncFailure(ctx context.Context, store db.Store, start time.Time, syncErr error) {
	duration := time.Since(start)
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncDuration: &duration,
		LastSyncStatus:   db.FeedSyncStatusError,
		LastError:        feed.SafeDiagnosticError(syncErr),
		UpdatedAt:        now,
	}
	if current, err := feed.GetFeedSyncStatusBounded(store, FeedName); err == nil {
		feed.PreserveFeedStatusData(status, current)
	}
	if err := feed.UpsertFeedSyncStatusBounded(store, status); err != nil {
		s.logger.Warn("failed to record endoflife sync failure", "error", err)
	}
	_ = ctx
}

func mapProduct(product Product) (db.LifecycleProduct, error) {
	productSlug := strings.TrimSpace(product.Name)
	if productSlug == "" {
		return db.LifecycleProduct{}, fmt.Errorf("product name is required")
	}
	name := strings.TrimSpace(product.Label)
	if name == "" {
		name = productSlug
	}

	identifiersJSON, _ := json.Marshal(product.Identifiers)
	rawJSON, _ := json.Marshal(product)
	mapped := db.LifecycleProduct{
		ProductSlug: productSlug,
		Name:        name,
		Category:    strings.TrimSpace(product.Category),
		Identifiers: identifiersJSON,
		Raw:         rawJSON,
		Releases:    make([]db.LifecycleRelease, 0, len(product.Releases)),
	}
	for _, release := range product.Releases {
		latest := ""
		if release.Latest != nil {
			latest = strings.TrimSpace(release.Latest.Name)
		}
		releaseDate, err := parseLifecycleDateStrict(productSlug, release.Name, "releaseDate", release.ReleaseDate)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		ltsFrom, err := parseLifecycleDateStrict(productSlug, release.Name, "ltsFrom", release.LTSFrom)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		eoasFrom, err := parseLifecycleDateStrict(productSlug, release.Name, "eoasFrom", release.EOASFrom)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		eolFrom, err := parseLifecycleDateStrict(productSlug, release.Name, "eolFrom", release.EOLFrom)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		discontinuedFrom, err := parseLifecycleDateStrict(productSlug, release.Name, "discontinuedFrom", release.DiscontinuedFrom)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		eoesFrom, err := parseLifecycleDateStrict(productSlug, release.Name, "eoesFrom", release.EOESFrom)
		if err != nil {
			return db.LifecycleProduct{}, err
		}
		releaseRaw, _ := json.Marshal(release)
		mapped.Releases = append(mapped.Releases, db.LifecycleRelease{
			ProductSlug:      productSlug,
			Cycle:            strings.TrimSpace(release.Name),
			Latest:           latest,
			ReleaseDate:      releaseDate,
			IsLTS:            release.IsLTS,
			LTSFrom:          ltsFrom,
			IsEOAS:           release.IsEOAS,
			EOASFrom:         eoasFrom,
			IsEOL:            release.IsEOL,
			EOLFrom:          eolFrom,
			IsDiscontinued:   release.IsDiscontinued,
			DiscontinuedFrom: discontinuedFrom,
			IsEOES:           release.IsEOES,
			EOESFrom:         eoesFrom,
			IsMaintained:     release.IsMaintained,
			Raw:              releaseRaw,
		})
	}

	mapSet := make(map[string]struct{})
	for _, identifier := range product.Identifiers {
		if !strings.EqualFold(strings.TrimSpace(identifier.Type), "purl") {
			continue
		}
		// Skip purl identifiers Packmon cannot map to a package ecosystem
		// (e.g. a pkg:github source-repo purl) or that are syntactically broken.
		// endoflife is an upstream feed we do not control; a single unmappable
		// identifier must not abort the whole sync. Non-purl identifiers are
		// already skipped above; unmappable purls are handled the same way, and
		// curated package maps still cover products that need explicit mapping.
		pkg, ok := sbom.PackageIdentityFromPURL(identifier.ID)
		if !ok {
			continue
		}
		purlType, purlNamespace, purlName := purlParts(identifier.ID)
		if purlType == "" || purlName == "" {
			continue
		}
		addPackageMap(&mapped, mapSet, db.LifecyclePackageMap{
			Ecosystem:     string(pkg.Ecosystem),
			Name:          pkg.Name,
			ProductSlug:   productSlug,
			PURLType:      purlType,
			PURLNamespace: purlNamespace,
			PURLName:      purlName,
			Source:        lifecycleSource,
		})
	}
	for _, packageMap := range lifecyclemaps.CuratedPackageMaps(productSlug) {
		addPackageMap(&mapped, mapSet, lifecyclePackageMap(packageMap))
	}
	return mapped, nil
}

func lifecyclePackageMap(packageMap lifecyclemaps.PackageMap) db.LifecyclePackageMap {
	return db.LifecyclePackageMap{
		Ecosystem:     packageMap.Ecosystem,
		Name:          packageMap.Name,
		ProductSlug:   packageMap.ProductSlug,
		PURLType:      packageMap.PURLType,
		PURLNamespace: packageMap.PURLNamespace,
		PURLName:      packageMap.PURLName,
		Source:        packageMap.Source,
	}
}

func addPackageMap(product *db.LifecycleProduct, set map[string]struct{}, packageMap db.LifecyclePackageMap) {
	if packageMap.ProductSlug == "" {
		packageMap.ProductSlug = product.ProductSlug
	}
	if packageMap.Source == "" {
		packageMap.Source = lifecycleSource
	}
	key := packageMap.Ecosystem + "\x00" + packageMap.Name + "\x00" + packageMap.ProductSlug
	if packageMap.Ecosystem == "" || packageMap.Name == "" {
		return
	}
	if _, ok := set[key]; ok {
		return
	}
	set[key] = struct{}{}
	product.PackageMaps = append(product.PackageMaps, packageMap)
}

func parseLifecycleDateStrict(productSlug, cycle, field, raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	date, err := time.Parse(time.DateOnly, raw)
	if err != nil {
		return nil, fmt.Errorf("product %q release %q field %s has invalid date %q", productSlug, strings.TrimSpace(cycle), field, raw)
	}
	return &date, nil
}

func purlParts(raw string) (purlType, purlNamespace, purlName string) {
	body := strings.TrimPrefix(strings.TrimSpace(raw), "pkg:")
	if idx := strings.IndexAny(body, "?#"); idx >= 0 {
		body = body[:idx]
	}
	if idx := strings.LastIndex(body, "@"); idx >= 0 {
		body = body[:idx]
	}
	typeName, path, ok := strings.Cut(body, "/")
	if !ok {
		return "", "", ""
	}
	purlType = strings.ToLower(strings.TrimSpace(typeName))
	rawSegments := strings.Split(path, "/")
	segments := make([]string, 0, len(rawSegments))
	for _, segment := range rawSegments {
		decoded, err := url.PathUnescape(segment)
		if err != nil || strings.TrimSpace(decoded) == "" {
			return purlType, "", ""
		}
		segments = append(segments, decoded)
	}
	if len(segments) == 0 {
		return purlType, "", ""
	}
	purlName = segments[len(segments)-1]
	if len(segments) > 1 {
		purlNamespace = strings.Join(segments[:len(segments)-1], "/")
	}
	return purlType, purlNamespace, purlName
}
