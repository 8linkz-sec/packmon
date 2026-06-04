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

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
	lifecyclemaps "github.com/8linkz/packmon/internal/lifecycle"
	"github.com/8linkz/packmon/internal/sbom"
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

type lifecycleReconciler interface {
	DeleteLifecycleProductsNotIn(ctx context.Context, productSlugs []string) (int, error)
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
		s.recordSyncSuccess(ctx, store, start, 0, 0, etag, syncMetadata{ETag: etag})
		return &feed.SyncResult{}, nil
	}

	products := make([]db.LifecycleProduct, 0, len(resp.Result))
	for _, product := range resp.Result {
		mapped := mapProduct(product)
		if mapped.ProductSlug == "" {
			continue
		}
		products = append(products, mapped)
	}

	if err := store.UpsertLifecycleProducts(ctx, products); err != nil {
		s.recordSyncFailure(ctx, store, start, err)
		return nil, fmt.Errorf("upsert lifecycle products: %w", err)
	}
	if reconciler, ok := store.(lifecycleReconciler); ok && len(products) > 0 {
		slugs := make([]string, 0, len(products))
		for _, product := range products {
			slugs = append(slugs, product.ProductSlug)
		}
		if _, err := reconciler.DeleteLifecycleProductsNotIn(ctx, slugs); err != nil {
			s.recordSyncFailure(ctx, store, start, err)
			return nil, fmt.Errorf("reconcile lifecycle products: %w", err)
		}
	}

	total := resp.Total
	if total == 0 {
		total = len(resp.Result)
	}
	metadata := syncMetadata{
		ETag:          etag,
		SchemaVersion: resp.SchemaVersion,
		GeneratedAt:   resp.GeneratedAt,
	}
	s.recordSyncSuccess(ctx, store, start, total, len(products), etag, metadata)
	return &feed.SyncResult{EntriesSynced: len(products), EntriesTotal: total}, nil
}

type syncMetadata struct {
	ETag          string `json:"etag,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
	GeneratedAt   string `json:"generated_at,omitempty"`
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
	if strings.TrimSpace(status.LastEtag) != "" {
		return strings.TrimSpace(status.LastEtag)
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

func (s *Syncer) recordSyncSuccess(ctx context.Context, store db.Store, start time.Time, total, synced int, etag string, metadata syncMetadata) {
	duration := time.Since(start)
	now := time.Now().UTC()
	if metadata.ETag == "" {
		metadata.ETag = etag
	}
	metadataJSON, _ := json.Marshal(metadata)
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "success",
		EntriesSynced:    synced,
		EntriesTotal:     total,
		LastEtag:         etag,
		Metadata:         metadataJSON,
	}); err != nil {
		s.logger.Warn("failed to record endoflife sync success", "error", err)
	}
}

func (s *Syncer) recordSyncFailure(ctx context.Context, store db.Store, start time.Time, syncErr error) {
	duration := time.Since(start)
	now := time.Now().UTC()
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "error",
		LastError:        syncErr.Error(),
	}); err != nil {
		s.logger.Warn("failed to record endoflife sync failure", "error", err)
	}
}

func mapProduct(product Product) db.LifecycleProduct {
	productSlug := strings.TrimSpace(product.Name)
	if productSlug == "" {
		return db.LifecycleProduct{}
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
		releaseRaw, _ := json.Marshal(release)
		mapped.Releases = append(mapped.Releases, db.LifecycleRelease{
			ProductSlug:      productSlug,
			Cycle:            strings.TrimSpace(release.Name),
			Latest:           latest,
			ReleaseDate:      parseLifecycleDate(release.ReleaseDate),
			IsLTS:            release.IsLTS,
			LTSFrom:          parseLifecycleDate(release.LTSFrom),
			IsEOAS:           release.IsEOAS,
			EOASFrom:         parseLifecycleDate(release.EOASFrom),
			IsEOL:            release.IsEOL,
			EOLFrom:          parseLifecycleDate(release.EOLFrom),
			IsDiscontinued:   release.IsDiscontinued,
			DiscontinuedFrom: parseLifecycleDate(release.DiscontinuedFrom),
			IsEOES:           release.IsEOES,
			EOESFrom:         parseLifecycleDate(release.EOESFrom),
			IsMaintained:     release.IsMaintained,
			Raw:              releaseRaw,
		})
	}

	mapSet := make(map[string]struct{})
	for _, identifier := range product.Identifiers {
		if !strings.EqualFold(strings.TrimSpace(identifier.Type), "purl") {
			continue
		}
		pkg, ok := sbom.PackageIdentityFromPURL(identifier.ID)
		if !ok {
			continue
		}
		purlType, purlNamespace, purlName := purlParts(identifier.ID)
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
		addPackageMap(&mapped, mapSet, packageMap)
	}
	return mapped
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

func parseLifecycleDate(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	date, err := time.Parse(time.DateOnly, raw)
	if err != nil {
		return nil
	}
	return &date
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
