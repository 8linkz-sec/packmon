package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

// listAllPackage is one detected dependency row for the section-2 full list.
type listAllPackage struct {
	Name       string
	Version    string
	Ecosystem  domain.Ecosystem
	LockFile   string
	SourceType string
	Dev        bool
	Direct     bool
	Indirect   bool
	Optional   bool
	Peer       bool
	Via        []string
	Parents    []domain.PackageParent
	SourceRefs []string
	// DeclaredVersion is the human-readable version hint next to an opaque
	// pin (GitHub Actions "# v1.2.3" comment); local reporting only.
	DeclaredVersion string
	Scope           string
	Relation        string
	Flags           string
	DockerRef       string
}

type listAllPackageReport struct {
	Target            string
	ScannedAt         string
	ScannedAtDateTime string
	Rows              []listAllRow
	Sources           []listAllSourceRow
	ScopeCounts       map[string]int
	WithUpdates       int
	Vulnerable        int
	Unknown           int
	Warnings          []string
	RefusedRequests   int
	SkippedRequests   int
	BreakerTripped    bool
	Offline           bool
}

type listAllRow struct {
	Name       string
	Installed  string
	Latest     string
	LatestCopy string
	Update     string
	Ecosystem  string
	Source     string
	Scope      string
	Relation   string
	Via        string
	Flags      string
	Vuln       string
	LockFile   string
}

type listAllFindingRow struct {
	Severity      string
	SeverityClass string
	Type          string
	RiskType      string
	Package       string
	Version       string
	Ecosystem     string
	Advisory      string
	AdvisoryURL   string
	Title         string
	FixedVersion  string
	Action        string
	Source        string
	Scope         string
	Relation      string
	Via           string
	Flags         string
}

type listAllFindingSection struct {
	Title     string
	Class     string
	AriaLabel string
	Findings  []listAllFindingRow
}

type listAllSourceRow struct {
	Kind string
	Path string
}

type listAllScopeSummary struct {
	Scope string
	Count int
}

var (
	resolveDockerImageStatusFn  = resolveDockerImageStatusWithDigestResolver
	inspectLocalDockerDigestsFn = inspectListAllLocalDockerDigests
	newDockerRegistryClientFunc = dockerimage.NewRegistryClient
)

type listAllScanPhaseResult struct {
	result     *domain.ScanResult
	failOn     domain.Severity
	exitCode   int
	collection *scanner.PackageCollection
	historyErr *scanHistoryRecordError
}

type listAllInventoryPhaseResult struct {
	packages []listAllPackage
	warnings []string
}

// runListAll runs the scanner pipeline once for findings and package
// collection, then reuses that collection to produce the full package list with
// available-update info. The terminal report keeps findings readable with a
// compact list-all layout while JSON, SARIF, and JUnit artifacts retain the
// standard scan result shape. The scanner's exit code is returned unchanged:
// --list-all is a reporting view and must not suppress a blocking exit code.
func runListAll(ctx context.Context, settings scanSettings) (int, error) {
	scan, err := runListAllScanOutputPhase(ctx, settings)
	if err != nil {
		return scan.exitCode, err
	}
	if settings.Quiet && strings.TrimSpace(settings.OutputHTML) == "" {
		return scan.exitCode, listAllScanHistoryError(scan)
	}

	inventory, err := collectListAllInventoryPhase(settings, scan.collection)
	if err != nil {
		return scan.exitCode, withDefaultExitCode(ExitOperational, err)
	}

	return writeListAllOutputPhase(ctx, settings, scan, inventory)
}

func runListAllScanOutputPhase(ctx context.Context, settings scanSettings) (listAllScanPhaseResult, error) {
	scanSettings := settings
	scanSettings.InventoryAll = true
	result, failOn, exitCode, _, collection, err := runScanPipeline(ctx, scanSettings)
	scan := listAllScanPhaseResult{
		result:     result,
		failOn:     failOn,
		exitCode:   exitCode,
		collection: collection,
	}
	if err != nil {
		var historyErr *scanHistoryRecordError
		if errors.As(err, &historyErr) {
			scan.historyErr = historyErr
			return scan, nil
		}
		return scan, withDefaultExitCode(exitCode, err)
	}

	if writeScanOutputArtifacts(settings, result, failOn, false) {
		scan.exitCode = ExitOperational
	}
	return scan, nil
}

func collectListAllInventoryPhase(settings scanSettings, collection *scanner.PackageCollection) (listAllInventoryPhaseResult, error) {
	packages, inventoryWarnings, err := listAllPackagesFromCollection(collection)
	if err != nil {
		return listAllInventoryPhaseResult{}, err
	}
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return listAllInventoryPhaseResult{}, withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
	}
	dockerRows, dockerWarnings, dockerErr := collectDockerPackagesWithWarnings(absPath, settings)
	if dockerErr != nil {
		warning := "docker inventory error: " + dockerErr.Error()
		inventoryWarnings = append(inventoryWarnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	} else {
		inventoryWarnings = append(inventoryWarnings, dockerWarnings...)
		packages = append(packages, dockerRows...)
	}
	return listAllInventoryPhaseResult{packages: packages, warnings: inventoryWarnings}, nil
}

func writeListAllOutputPhase(ctx context.Context, settings scanSettings, scan listAllScanPhaseResult, inventory listAllInventoryPhaseResult) (int, error) {
	resolver := settings.resolver
	resolver.latestRegistry = resolver.latestRegistry.inheritFallback(settings.LatestRegistry)
	packageReport := buildListAllPackageReportWithOptions(ctx, inventory.packages, scan.result, settings.Path, settings.Timeout, listAllPackageReportOptions{
		Offline:  settings.ListAllOffline,
		Quiet:    settings.Quiet,
		resolver: resolver,
	})
	packageReport.Warnings = append(packageReport.Warnings, inventory.warnings...)
	packageReport.Sources = mergeListAllSourceRows(packageReport.Sources, listAllExplicitSBOMSources(settings))
	htmlWritten := false
	if settings.OutputHTML != "" {
		if err := writeListAllHTML(settings.OutputHTML, settings.TargetName, scan.result, packageReport); err != nil {
			return scan.exitCode, withDefaultExitCode(ExitOperational, err)
		}
		htmlWritten = true
	}

	if settings.Quiet {
		return scan.exitCode, listAllScanHistoryError(scan)
	}

	if err := writeListAllSecurityFindings(os.Stdout, scan.result, scan.failOn, packageReport, settings.NoColor); err != nil {
		fmt.Fprintf(os.Stderr, "error writing list-all findings output: %v\n", err)
	}

	// A few blank lines separate the findings and inventory sections.
	fmt.Print("\n\n\n")

	if len(inventory.packages) == 0 {
		fmt.Println("No packages found.")
		if htmlWritten {
			fmt.Printf("HTML report written to: %s\n", settings.OutputHTML)
		}
		return scan.exitCode, listAllScanHistoryError(scan)
	}

	printListAllPackageReport(packageReport)
	if htmlWritten {
		fmt.Printf("HTML report written to: %s\n", settings.OutputHTML)
	}
	return scan.exitCode, listAllScanHistoryError(scan)
}

func listAllScanHistoryError(scan listAllScanPhaseResult) error {
	if scan.historyErr == nil {
		return nil
	}
	return scan.historyErr
}

func listAllPackagesFromCollection(collection *scanner.PackageCollection) ([]listAllPackage, []string, error) {
	if collection == nil {
		return nil, nil, nil
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return nil, nil, err
	}
	seen := make(map[string]struct{})
	var packages []listAllPackage
	var warnings []string
	for _, parseErr := range collection.ParseErrors {
		warning := "parse error in " + parseErr
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, listAllPackage{
			Name:            p.Name,
			Version:         p.Version,
			Ecosystem:       p.Ecosystem,
			LockFile:        entry.SourceFile,
			SourceType:      entry.SourceType,
			Dev:             p.Dev,
			Direct:          p.Direct,
			Indirect:        p.Indirect,
			Optional:        p.Optional,
			Peer:            p.Peer,
			Via:             append([]string(nil), p.Via...),
			Parents:         append([]domain.PackageParent(nil), p.Parents...),
			SourceRefs:      append([]string(nil), p.SourceRefs...),
			DeclaredVersion: p.DeclaredVersion,
		})
	}

	return packages, warnings, nil
}

func collectDockerPackagesWithWarnings(absPath string, settings scanSettings) ([]listAllPackage, []string, error) {
	if !listAllAllowsDocker(settings.Ecosystems) {
		return nil, nil, nil
	}
	collection, err := dockerimage.Collect(absPath, settings.MaxDepth)
	if err != nil {
		return nil, nil, err
	}
	var warnings []string
	for _, discoveryWarning := range collection.DiscoveryWarnings {
		warning := "docker discovery warning in " + discoveryWarning
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	for _, parseErr := range collection.ParseErrors {
		warning := "docker parse error in " + parseErr
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	rows := make([]listAllPackage, 0, len(collection.Images))
	for _, image := range collection.Images {
		pkg := image.Package()
		rows = append(rows, listAllPackage{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Ecosystem:  pkg.Ecosystem,
			LockFile:   image.SourceFile,
			SourceType: string(image.SourceType),
			Direct:     pkg.Direct,
			Indirect:   pkg.Indirect,
			Scope:      image.Scope,
			Relation:   image.Relation,
			Flags:      strings.Join(image.Flags, ", "),
			DockerRef:  image.Ref.Original,
		})
	}
	return rows, warnings, nil
}

func listAllAllowsDocker(ecosystems []string) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, raw := range ecosystems {
		if strings.EqualFold(strings.TrimSpace(raw), string(domain.EcosystemDocker)) {
			return true
		}
	}
	return false
}

type listAllPackageReportOptions struct {
	Offline  bool
	Quiet    bool
	resolver packageUpdateResolver
}

func buildListAllPackageReportWithOptions(parent context.Context, packages []listAllPackage, result *domain.ScanResult, scanPath string, timeoutSeconds int, options listAllPackageReportOptions) listAllPackageReport {
	// Look up latest versions in parallel with a bounded request fan-out
	// with per-request timeouts; the phase has no deadline.
	ctx, phase := withRegistryLookupPhase(parent, timeoutSeconds)

	latest := make([]packageLatestStatus, len(packages))
	if options.Offline {
		for i := range latest {
			latest[i] = packageLatestStatus{Latest: "unknown", Update: "-", Unknown: true}
		}
	} else {
		cargoCount := 0
		for _, p := range packages {
			if p.Ecosystem == domain.EcosystemCargo {
				cargoCount++
			}
		}
		announceLookupPhase(os.Stderr, len(packages), cargoCount, options.Quiet)
		lookup := newCachedPackageUpdateLookupWithResolver(options.resolver)
		// Scoped to this call only: a hung docker daemon must not block the
		// whole lookup phase, which otherwise carries no deadline.
		localDockerDigests := func() map[string]string {
			ctx, cancel := perRequestLookupContext(ctx)
			defer cancel()
			return inspectLocalDockerDigestsFn(ctx, packages)
		}()
		var dockerDigestLookup dockerDigestResolver
		if listAllContainsDockerPackage(packages) {
			dockerDigestLookup = newCachedDockerDigestLookup(newDockerRegistryClientWithMirrors(options.resolver.latestRegistry))
		}
		progress := startLookupProgress(os.Stderr, len(packages), options.Quiet, lookupProgressInterval)
		latest = resolveLatestWithWorkerPool(ctx, packages, func(ctx context.Context, p listAllPackage) packageLatestStatus {
			defer progress.increment()
			return resolveListAllLatestWithCachedDockerLookup(ctx, p, lookup, localDockerDigests, dockerDigestLookup)
		})
		progress.stop()
	}

	// Index vulnerability findings by ecosystem+name+version for the VULN column.
	vulnSet := make(map[string]struct{})
	if result != nil {
		for _, f := range result.Findings {
			if f.Type == domain.FindingTypeVulnerability {
				vulnSet[string(f.Ecosystem)+"/"+f.Name+"@"+f.Version] = struct{}{}
			}
		}
	}

	scannedAt := time.Now().UTC()
	report := listAllPackageReport{
		Target:            scanPath,
		ScannedAt:         formatReportTimestamp(scannedAt),
		ScannedAtDateTime: formatReportTimestampDateTime(scannedAt),
		Rows:              make([]listAllRow, 0, len(packages)),
		ScopeCounts:       make(map[string]int),
		Offline:           options.Offline,
	}
	for i, p := range packages {
		lat := latest[i]
		latestCol := lat.Latest
		update := lat.Update
		if latestCol == "" {
			latestCol = "unknown"
		}
		if update == "" {
			update = "-"
		}
		if lat.Unknown {
			report.Unknown++
		}
		if update == "yes" {
			report.WithUpdates++
		}

		vuln := "-"
		if _, ok := vulnSet[string(p.Ecosystem)+"/"+p.Name+"@"+p.Version]; ok {
			vuln = "yes"
			report.Vulnerable++
		}

		status := packageStatusFromListAllPackage(p)
		scope := packageStatusScope(status)
		report.ScopeCounts[scope]++
		report.Rows = append(report.Rows, listAllRow{
			Name:       p.Name,
			Installed:  p.Version,
			Latest:     latestCol,
			LatestCopy: lat.LatestCopy,
			Update:     update,
			Ecosystem:  string(p.Ecosystem),
			Source:     listAllPackageSource(p),
			Scope:      scope,
			Relation:   packageStatusRelation(status),
			Via:        strings.Join(p.Via, ", "),
			Flags:      packageStatusFlags(status),
			Vuln:       vuln,
			LockFile:   p.LockFile,
		})
	}

	// Sort: ecosystem, then name, then version.
	sort.Slice(report.Rows, func(i, j int) bool {
		if report.Rows[i].Ecosystem != report.Rows[j].Ecosystem {
			return report.Rows[i].Ecosystem < report.Rows[j].Ecosystem
		}
		if report.Rows[i].Name != report.Rows[j].Name {
			return report.Rows[i].Name < report.Rows[j].Name
		}
		return report.Rows[i].Installed < report.Rows[j].Installed
	})
	report.Sources = listAllCheckedInventorySources(report.Rows)
	appendLookupPhaseWarnings(&report, phase, ctx.Err() != nil)

	return report
}

// appendLookupPhaseWarnings records the phase counters on the report and emits
// the matching warnings. A canceled phase records counters but stays silent:
// the user aborted, nothing failed.
func appendLookupPhaseWarnings(report *listAllPackageReport, phase *registryLookupPhase, canceled bool) {
	report.RefusedRequests = phase.refusedCount()
	report.SkippedRequests = phase.skippedCount()
	report.BreakerTripped = phase.breakerOpen()
	if canceled {
		return
	}
	if report.RefusedRequests > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%d registry requests were refused or failed, so some latest-version data is missing and the update status of the affected rows is incomplete. A registry rate limit or a slow registry is the usual cause -- rerun the scan, raise --timeout, or route the lookups through a mirror.",
			report.RefusedRequests,
		))
	}
	if report.BreakerTripped {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%d lookups were skipped after %d consecutive registry request failures; latest-version lookups were aborted. Check network connectivity and proxy settings, then rerun the scan.",
			report.SkippedRequests, registryBreakerThreshold,
		))
	}
}

func listAllContainsDockerPackage(packages []listAllPackage) bool {
	for _, p := range packages {
		if p.Ecosystem == domain.EcosystemDocker {
			return true
		}
	}
	return false
}

func newDockerRegistryClientWithMirrors(registry latestRegistryConfig) *dockerimage.RegistryClient {
	client := newDockerRegistryClientFunc(nil)
	if client != nil {
		client.Mirrors = registry.withDefaults().DockerRegistryMirrors
	}
	return client
}

func resolveListAllLatestWithLookup(ctx context.Context, p listAllPackage, lookup packageUpdateLookup, localDockerDigests map[string]string) packageLatestStatus {
	return resolveListAllLatestWithCachedDockerLookup(ctx, p, lookup, localDockerDigests, nil)
}

func resolveListAllLatestWithCachedDockerLookup(ctx context.Context, p listAllPackage, lookup packageUpdateLookup, localDockerDigests map[string]string, dockerDigests dockerDigestResolver) packageLatestStatus {
	if p.Ecosystem == domain.EcosystemDocker {
		return resolveDockerImageStatusFn(ctx, p, localDockerDigests, dockerDigests)
	}
	if !latestLookupAllowed(p.Ecosystem, p.SourceRefs, lookup) {
		return unknownLatestStatus()
	}
	return resolvePackageUpdateStatusWithLookup(ctx, packageUpdateQuery{
		name:      p.Name,
		installed: p.Version,
		declared:  p.DeclaredVersion,
		ecosystem: p.Ecosystem,
		direct:    p.Direct,
		parents:   p.Parents,
	}, lookup)
}

func inspectListAllLocalDockerDigests(ctx context.Context, packages []listAllPackage) map[string]string {
	refs := make([]dockerimage.Ref, 0)
	seen := make(map[string]struct{})
	for _, p := range packages {
		if p.Ecosystem != domain.EcosystemDocker {
			continue
		}
		ref, ok := dockerRefFromListAllPackage(p)
		if !ok || ref.Digest || strings.HasPrefix(p.Name, "local/") {
			continue
		}
		key := ref.Name + ":" + ref.Reference
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil
	}
	return dockerimage.LocalInspector{}.Digests(ctx, refs)
}

func listAllPackageSource(p listAllPackage) string {
	source := strings.TrimSpace(p.SourceType)
	if source != "" {
		return source
	}
	if p.Ecosystem == domain.EcosystemDocker {
		return "docker"
	}
	if strings.TrimSpace(p.LockFile) != "" {
		return "lockfile"
	}
	return "-"
}

func resolveDockerImageStatusWithLocalDigests(ctx context.Context, p listAllPackage, localDigests map[string]string) packageLatestStatus {
	return resolveDockerImageStatusWithDigestResolver(ctx, p, localDigests, nil)
}

type dockerDigestResolver interface {
	ResolveDigest(context.Context, dockerimage.Ref) (string, error)
}

type cachedDockerDigestLookup struct {
	resolver dockerDigestResolver
	mu       sync.Mutex
	digests  map[dockerDigestCacheKey]dockerDigestCacheEntry
	inflight map[dockerDigestCacheKey]*dockerDigestCacheCall
}

type dockerDigestCacheKey struct {
	registry   string
	repository string
	reference  string
}

type dockerDigestCacheEntry struct {
	digest string
	err    error
}

type dockerDigestCacheCall struct {
	done   chan struct{}
	digest string
	err    error
}

func newCachedDockerDigestLookup(resolver dockerDigestResolver) *cachedDockerDigestLookup {
	if resolver == nil {
		resolver = newDockerRegistryClientFunc(nil)
	}
	return &cachedDockerDigestLookup{
		resolver: resolver,
		digests:  make(map[dockerDigestCacheKey]dockerDigestCacheEntry),
		inflight: make(map[dockerDigestCacheKey]*dockerDigestCacheCall),
	}
}

func (l *cachedDockerDigestLookup) ResolveDigest(ctx context.Context, ref dockerimage.Ref) (string, error) {
	if l == nil || l.resolver == nil {
		return newDockerRegistryClientFunc(nil).ResolveDigest(ctx, ref)
	}
	key, ok := dockerDigestLookupCacheKey(ref)
	if !ok {
		return l.resolver.ResolveDigest(ctx, ref)
	}

	l.mu.Lock()
	if entry, ok := l.digests[key]; ok {
		l.mu.Unlock()
		return entry.digest, entry.err
	}
	if call, ok := l.inflight[key]; ok {
		l.mu.Unlock()
		select {
		case <-call.done:
			return call.digest, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	call := &dockerDigestCacheCall{done: make(chan struct{})}
	l.inflight[key] = call
	l.mu.Unlock()

	digest, err := l.resolver.ResolveDigest(ctx, ref)

	l.mu.Lock()
	call.digest = digest
	call.err = err
	l.digests[key] = dockerDigestCacheEntry{digest: digest, err: err}
	delete(l.inflight, key)
	close(call.done)
	l.mu.Unlock()
	return digest, err
}

func dockerDigestLookupCacheKey(ref dockerimage.Ref) (dockerDigestCacheKey, bool) {
	if ref.Registry == "" || ref.Repository == "" || ref.Reference == "" {
		return dockerDigestCacheKey{}, false
	}
	return dockerDigestCacheKey{
		registry:   ref.Registry,
		repository: ref.Repository,
		reference:  ref.Reference,
	}, true
}

func resolveDockerImageStatusWithDigestResolver(ctx context.Context, p listAllPackage, localDigests map[string]string, registryClient dockerDigestResolver) packageLatestStatus {
	ref, ok := dockerRefFromListAllPackage(p)
	if !ok {
		return packageLatestStatus{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	if strings.HasPrefix(p.Name, "local/") {
		return packageLatestStatus{Latest: "-", Update: "local"}
	}
	if registryClient == nil {
		registryClient = newDockerRegistryClientFunc(nil)
	}
	if ref.Digest {
		tagRef, ok := dockerTagRefFromPinnedRef(ref)
		if !ok {
			return packageLatestStatus{Latest: "-", Update: "pinned"}
		}
		currentDigest, err := registryClient.ResolveDigest(ctx, tagRef)
		if err != nil {
			// An attempted resolution that errored, not a deliberate skip --
			// counts toward the honest-warning accounting unless it is a
			// client-side policy rejection (never reached the network) or the
			// phase context was itself canceled (the user's decision, not a
			// failure).
			if !errors.Is(err, dockerimage.ErrRegistryUnsupported) && ctx.Err() == nil {
				registryLookupPhaseFrom(ctx).recordRefusal()
			}
			return packageLatestStatus{Latest: "-", Update: "pinned"}
		}
		if currentDigest == "" {
			return packageLatestStatus{Latest: "-", Update: "pinned"}
		}
		if !strings.EqualFold(currentDigest, ref.Reference) {
			return packageLatestStatus{Latest: shortDigest(currentDigest), LatestCopy: currentDigest, Update: "yes"}
		}
		return packageLatestStatus{Latest: shortDigest(currentDigest), LatestCopy: currentDigest, Update: "pinned"}
	}
	remoteDigest, err := registryClient.ResolveDigest(ctx, ref)
	if err != nil {
		if !errors.Is(err, dockerimage.ErrRegistryUnsupported) && ctx.Err() == nil {
			registryLookupPhaseFrom(ctx).recordRefusal()
		}
		return packageLatestStatus{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	if remoteDigest == "" {
		return packageLatestStatus{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	if localDigests == nil {
		// Scoped to this call only: a hung docker daemon must not block the
		// whole lookup phase, which otherwise carries no deadline.
		localDigests = func() map[string]string {
			inspectCtx, cancel := perRequestLookupContext(ctx)
			defer cancel()
			return dockerimage.LocalInspector{}.Digests(inspectCtx, []dockerimage.Ref{ref})
		}()
	}
	localDigest := localDigests[ref.Name]
	if localDigest == "" {
		return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "unknown", Unknown: true}
	}
	if localDigest != remoteDigest {
		return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "yes"}
	}
	return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "-"}
}

func dockerRefFromListAllPackage(p listAllPackage) (dockerimage.Ref, bool) {
	raw := p.Name + ":" + p.Version
	if dockerRef := strings.TrimSpace(p.DockerRef); dockerRef != "" {
		raw = dockerRef
	}
	if strings.Contains(p.Version, ":") {
		raw = p.Name + "@" + p.Version
		if dockerRef := strings.TrimSpace(p.DockerRef); dockerRef != "" {
			raw = dockerRef
		}
	}
	return dockerimage.ParseRef(raw)
}

func dockerTagRefFromPinnedRef(ref dockerimage.Ref) (dockerimage.Ref, bool) {
	raw := strings.TrimSpace(ref.Original)
	namePart, _, ok := strings.Cut(raw, "@")
	if !ok {
		return dockerimage.Ref{}, false
	}
	colon := strings.LastIndex(namePart, ":")
	if colon <= strings.LastIndex(namePart, "/") {
		return dockerimage.Ref{}, false
	}
	return dockerimage.ParseRef(namePart)
}

func shortDigest(digest string) string {
	_, value, ok := strings.Cut(digest, ":")
	if !ok || len(value) <= 17 {
		return digest
	}
	return value[:17] + ".."
}

func printListAllPackageReport(report listAllPackageReport) {
	rows := make([]listAllRow, 0, len(report.Rows))
	for _, r := range report.Rows {
		rows = append(rows, sanitizeListAllTerminalRow(r))
	}

	// Column widths (header widths as the minimum).
	maxName, maxInst, maxLat, maxUpd, maxEco, maxSource, maxScope, maxRel, maxVia, maxFlags, maxVuln := 7, 9, 6, 6, 9, 6, 5, 8, 3, 5, 4
	for _, r := range rows {
		maxName = maxInt(maxName, len(r.Name))
		maxInst = maxInt(maxInst, len(r.Installed))
		maxLat = maxInt(maxLat, len(r.Latest))
		maxUpd = maxInt(maxUpd, len(r.Update))
		maxEco = maxInt(maxEco, len(r.Ecosystem))
		maxSource = maxInt(maxSource, len(r.Source))
		maxScope = maxInt(maxScope, len(r.Scope))
		maxRel = maxInt(maxRel, len(r.Relation))
		maxVia = maxInt(maxVia, len(r.Via))
		maxFlags = maxInt(maxFlags, len(r.Flags))
		maxVuln = maxInt(maxVuln, len(r.Vuln))
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxSource, gap, maxScope, gap, maxRel, gap, maxVia, gap, maxFlags, gap, maxVuln, gap)

	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SOURCE", "SCOPE", "RELATION", "VIA", "FLAGS", "VULNERABILITY", "SOURCE FILE")
	for _, r := range rows {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Source, r.Scope, r.Relation, r.Via, r.Flags, r.Vuln, r.LockFile)
	}

	fmt.Printf("\n%s (%s, %s, %s)\n",
		plural.Count(len(rows), "package", "packages"),
		plural.Count(report.WithUpdates, "with update", "with updates"),
		plural.Count(report.Vulnerable, "vulnerability", "vulnerabilities"),
		plural.Count(report.Unknown, "unknown", "unknown"))
}

func writeListAllSecurityFindings(w io.Writer, result *domain.ScanResult, failOn domain.Severity, report listAllPackageReport, noColor bool) error {
	if _, err := fmt.Fprintln(w, "Security Findings"); err != nil {
		return err
	}
	if result == nil {
		_, err := fmt.Fprintln(w, "\nScan did not complete; findings were not evaluated.")
		return err
	}
	if len(result.Findings) == 0 {
		tw := scanner.NewTableWriter(noColor, failOn)
		return tw.Write(w, result)
	}
	if err := writeListAllTerminalFindingStatusMessages(w, result); err != nil {
		return err
	}

	sections := listAllFindingSections(listAllFindingRows(result.Findings, report.Rows))
	for _, section := range sections {
		if _, err := fmt.Fprintf(w, "\n%s (%d)\n", termtext.Sanitize(section.Title), len(section.Findings)); err != nil {
			return err
		}
		if err := writeListAllTerminalFindingTable(w, section.Findings, noColor); err != nil {
			return err
		}
	}
	return writeListAllTerminalFindingSummary(w, result, failOn)
}

func writeListAllTerminalFindingStatusMessages(w io.Writer, result *domain.ScanResult) error {
	if result == nil {
		return nil
	}
	if message := scanner.LocalDBStaleWarning(result); message != "" {
		if _, err := fmt.Fprintf(w, "\n!! ATTENTION: %s\n", message); err != nil {
			return err
		}
	}

	if statusMessage := listAllOperationalStatusForResult(result); statusMessage != "" {
		_, err := fmt.Fprintf(w, "\n%s\n", termtext.Sanitize(statusMessage))
		return err
	}
	if result.FeedStatus == string(domain.ScanFeedStatusDegraded) {
		_, err := fmt.Fprintln(w, "\nWARN  "+scanner.DegradedFeedStatusWarning(result.Mode))
		return err
	}
	return nil
}

func writeListAllTerminalFindingTable(w io.Writer, rows []listAllFindingRow, noColor bool) error {
	terminalRows := make([]listAllFindingRow, 0, len(rows))
	maxSeverity, maxPackage, maxAdvisory, maxFinding := 8, 7, 8, 7
	for _, row := range rows {
		row = sanitizeListAllTerminalFindingRow(row)
		terminalRows = append(terminalRows, row)
		maxSeverity = maxInt(maxSeverity, len(row.Severity))
		maxPackage = maxInt(maxPackage, len(row.Package))
		maxAdvisory = maxInt(maxAdvisory, len(row.Advisory))
		maxFinding = maxInt(maxFinding, len(row.Title))
	}

	gap := "  "
	headerFormat := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxSeverity, gap, maxPackage, gap, maxAdvisory, gap, maxFinding, gap)
	if _, err := fmt.Fprintf(w, headerFormat, "SEVERITY", "PACKAGE", "ADVISORY", "FINDING", "ACTION"); err != nil {
		return err
	}

	rowFormat := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxPackage, gap, maxAdvisory, gap, maxFinding, gap)
	for _, row := range terminalRows {
		if err := writeListAllTerminalFindingRow(w, row, rowFormat, maxSeverity, noColor); err != nil {
			return err
		}
		if details := listAllTerminalFindingDetails(row); details != "" {
			if _, err := fmt.Fprintf(w, "  Details: %s\n", details); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeListAllTerminalFindingRow(w io.Writer, row listAllFindingRow, rowFormat string, severityWidth int, noColor bool) error {
	severity := listAllTerminalSeverity(domain.Severity(row.Severity), noColor)
	pad := ""
	if diff := severityWidth - len(row.Severity); diff > 0 {
		pad = strings.Repeat(" ", diff)
	}
	if _, err := fmt.Fprintf(w, "%s%s  ", severity, pad); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, rowFormat, row.Package, row.Advisory, row.Title, row.Action)
	return err
}

func listAllTerminalSeverity(severity domain.Severity, noColor bool) string {
	text := string(severity)
	if noColor {
		return text
	}
	switch severity {
	case domain.SeverityCritical:
		return "\033[1m\033[31m" + text + "\033[0m"
	case domain.SeverityHigh:
		return "\033[31m" + text + "\033[0m"
	case domain.SeverityMedium:
		return "\033[33m" + text + "\033[0m"
	case domain.SeverityLow:
		return "\033[36m" + text + "\033[0m"
	default:
		return "\033[37m" + text + "\033[0m"
	}
}

func writeListAllTerminalFindingSummary(w io.Writer, result *domain.ScanResult, failOn domain.Severity) error {
	blocking := 0
	for _, finding := range result.Findings {
		if domain.FindingBlocks(finding, failOn) {
			blocking++
		}
	}
	if blocking == 0 && result.FindingsBlocking && len(result.Findings) > 0 {
		blocking = 1
	}
	_, err := fmt.Fprintf(w, "\nFound %s (%s) in %s\n",
		plural.Count(result.FindingsCount, "finding", "findings"),
		plural.Count(blocking, "blocking", "blocking"),
		plural.Count(result.PackagesScanned, "package", "packages"))
	return err
}

func sanitizeListAllTerminalFindingRow(row listAllFindingRow) listAllFindingRow {
	return listAllFindingRow{
		Severity:      termtext.Sanitize(row.Severity),
		SeverityClass: row.SeverityClass,
		Type:          termtext.Sanitize(row.Type),
		RiskType:      termtext.Sanitize(row.RiskType),
		Package:       termtext.Sanitize(row.Package),
		Version:       termtext.Sanitize(row.Version),
		Ecosystem:     termtext.Sanitize(row.Ecosystem),
		Advisory:      termtext.Sanitize(row.Advisory),
		AdvisoryURL:   row.AdvisoryURL,
		Title:         termtext.Sanitize(row.Title),
		FixedVersion:  termtext.Sanitize(row.FixedVersion),
		Action:        termtext.Sanitize(row.Action),
		Source:        termtext.Sanitize(row.Source),
		Scope:         termtext.Sanitize(row.Scope),
		Relation:      termtext.Sanitize(row.Relation),
		Via:           termtext.Sanitize(row.Via),
		Flags:         termtext.Sanitize(row.Flags),
	}
}

func listAllTerminalFindingDetails(row listAllFindingRow) string {
	pairs := []struct {
		label string
		value string
	}{
		{"Action", row.Action},
		{"Type", row.Type},
		{"Risk", row.RiskType},
		{"Installed", row.Version},
		{"Ecosystem", row.Ecosystem},
		{"Source", row.Source},
		{"Scope", row.Scope},
		{"Relation", row.Relation},
		{"Fixed Version", row.FixedVersion},
	}
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		value := strings.TrimSpace(pair.value)
		if value == "" {
			value = "-"
		}
		parts = append(parts, pair.label+": "+value)
	}
	return strings.Join(parts, "; ")
}

func sanitizeListAllTerminalRow(r listAllRow) listAllRow {
	return listAllRow{
		Name:       termtext.Sanitize(r.Name),
		Installed:  termtext.Sanitize(r.Installed),
		Latest:     termtext.Sanitize(r.Latest),
		LatestCopy: r.LatestCopy,
		Update:     termtext.Sanitize(r.Update),
		Ecosystem:  termtext.Sanitize(r.Ecosystem),
		Source:     termtext.Sanitize(r.Source),
		Scope:      termtext.Sanitize(r.Scope),
		Relation:   termtext.Sanitize(r.Relation),
		Via:        termtext.Sanitize(r.Via),
		Flags:      termtext.Sanitize(r.Flags),
		Vuln:       termtext.Sanitize(r.Vuln),
		LockFile:   termtext.Sanitize(r.LockFile),
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func listAllFindingRows(findings []domain.Finding, packageRows []listAllRow) []listAllFindingRow {
	rows := make([]listAllFindingRow, 0, len(findings))
	for _, f := range findings {
		meta := listAllFindingMetadata(packageRows, f)
		severity := domain.NormalizeFindingSeverity(f)
		row := listAllFindingRow{
			Severity:      string(severity),
			SeverityClass: listAllSeverityClass(severity),
			Type:          listAllFindingTypeLabel(f),
			RiskType:      listAllFindingRiskType(f),
			Package:       listAllFindingPackageLabel(f),
			Version:       f.Version,
			Ecosystem:     string(f.Ecosystem),
			Advisory:      listAllAdvisoryLabel(f),
			AdvisoryURL:   listAllAdvisoryURL(f),
			Title:         listAllFindingTitle(f),
			FixedVersion:  f.FixedVersion,
			Source:        f.Source,
			Scope:         meta.Scope,
			Relation:      meta.Relation,
			Via:           meta.Via,
			Flags:         meta.Flags,
		}
		row.Action = listAllFindingAction(row)
		rows = append(rows, row)
	}
	return rows
}

func listAllFindingMetadata(rows []listAllRow, finding domain.Finding) listAllRow {
	key := listAllFindingKey(finding)
	var match listAllRow
	for _, row := range rows {
		if listAllRowFindingKey(row) == key {
			match = row
		}
	}
	return match
}

func listAllFindingAction(row listAllFindingRow) string {
	if fixed := strings.TrimSpace(row.FixedVersion); fixed != "" {
		return "Fix " + fixed
	}
	switch row.Type {
	case "Malicious":
		return "Remove package"
	case "Supply-chain":
		if strings.EqualFold(strings.TrimSpace(row.RiskType), "Malware history") {
			return "Review history"
		}
		return "Review package"
	case "Lifecycle":
		return "Review lifecycle"
	case "Reputation info":
		return "Review history"
	case "Vulnerability":
		return "Review advisory"
	default:
		return "Review finding"
	}
}

func listAllCheckedInventorySources(rows []listAllRow) []listAllSourceRow {
	seen := make(map[string]struct{})
	for _, row := range rows {
		lockFile := strings.TrimSpace(row.LockFile)
		if lockFile == "" {
			continue
		}
		kind := listAllInventorySourceKind(row)
		seen[kind+"\x00"+lockFile] = struct{}{}
	}
	out := make([]listAllSourceRow, 0, len(seen))
	for key := range seen {
		kind, path, _ := strings.Cut(key, "\x00")
		out = append(out, listAllSourceRow{Kind: kind, Path: path})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func listAllExplicitSBOMSources(settings scanSettings) []listAllSourceRow {
	if len(settings.SBOMFiles) == 0 {
		return nil
	}
	root, err := filepath.Abs(settings.Path)
	if err != nil {
		root = settings.Path
	}
	out := make([]listAllSourceRow, 0, len(settings.SBOMFiles))
	for _, raw := range settings.SBOMFiles {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		path := raw
		if abs, absErr := filepath.Abs(raw); absErr == nil {
			path = listAllDisplayRelativePath(root, abs)
		}
		out = append(out, listAllSourceRow{Kind: "sbom", Path: filepath.ToSlash(path)})
	}
	return listAllSortAndDedupSources(out)
}

func mergeListAllSourceRows(left, right []listAllSourceRow) []listAllSourceRow {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	out := make([]listAllSourceRow, 0, len(left)+len(right))
	out = append(out, left...)
	out = append(out, right...)
	return listAllSortAndDedupSources(out)
}

func listAllSortAndDedupSources(sources []listAllSourceRow) []listAllSourceRow {
	seen := make(map[string]listAllSourceRow, len(sources))
	for _, source := range sources {
		source.Kind = strings.ToLower(strings.TrimSpace(source.Kind))
		source.Path = strings.TrimSpace(source.Path)
		if source.Kind == "" || source.Path == "" {
			continue
		}
		seen[source.Kind+"\x00"+source.Path] = source
	}
	out := make([]listAllSourceRow, 0, len(seen))
	for _, source := range seen {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func listAllDisplayRelativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return safeHTMLExternalPath(path)
	}
	return rel
}

func listAllInventorySourceKind(row listAllRow) string {
	source := strings.ToLower(strings.TrimSpace(row.Source))
	switch source {
	case "dockerfile", "compose", "docker":
		return "docker"
	case "sbom":
		return "sbom"
	case "lockfile":
		return "lockfile"
	}
	if strings.EqualFold(strings.TrimSpace(row.Ecosystem), string(domain.EcosystemDocker)) {
		return "docker"
	}
	if listAllRowLooksLikeSBOM(row) {
		return "sbom"
	}
	return "lockfile"
}

func listAllRowLooksLikeSBOM(row listAllRow) bool {
	if strings.EqualFold(strings.TrimSpace(row.Scope), "sbom") {
		return true
	}
	path := strings.ToLower(strings.TrimSpace(filepath.ToSlash(row.LockFile)))
	return strings.HasSuffix(path, ".cdx.json") ||
		strings.HasSuffix(path, ".spdx.json") ||
		strings.HasSuffix(path, ".spdx")
}

func listAllSeverityClass(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical:
		return "sev-critical"
	case domain.SeverityHigh:
		return "sev-high"
	case domain.SeverityMedium:
		return "sev-medium"
	case domain.SeverityLow:
		return "sev-low"
	default:
		return "sev-unknown"
	}
}

func listAllFindingKey(f domain.Finding) string {
	return string(f.Ecosystem) + "/" + f.Name + "@" + f.Version
}

func listAllRowFindingKey(row listAllRow) string {
	return row.Ecosystem + "/" + row.Name + "@" + row.Installed
}

func listAllScopeSummaries(report listAllPackageReport) []listAllScopeSummary {
	counts := report.ScopeCounts
	if len(counts) == 0 && len(report.Rows) > 0 {
		counts = make(map[string]int)
		for _, row := range report.Rows {
			if strings.TrimSpace(row.Scope) != "" {
				counts[row.Scope]++
			}
		}
	}
	if len(counts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(counts))
	order := []string{"runtime", "dev", "ci", "sbom", "build"}
	out := make([]listAllScopeSummary, 0, len(counts))
	for _, scope := range order {
		if count := counts[scope]; count > 0 {
			out = append(out, listAllScopeSummary{Scope: scope, Count: count})
			seen[scope] = struct{}{}
		}
	}
	var rest []string
	for scope, count := range counts {
		if count <= 0 {
			continue
		}
		if _, ok := seen[scope]; !ok {
			rest = append(rest, scope)
		}
	}
	sort.Strings(rest)
	for _, scope := range rest {
		out = append(out, listAllScopeSummary{Scope: scope, Count: counts[scope]})
	}
	return out
}

func listAllOperationalStatus(status string) string {
	status = strings.TrimSpace(status)
	switch status {
	case "", string(domain.ScanFeedStatusHealthy), string(domain.ScanFeedStatusDegraded):
		return ""
	default:
		return status
	}
}

func listAllOperationalStatusForResult(result *domain.ScanResult) string {
	if result == nil {
		return ""
	}
	if message := strings.TrimSpace(result.ScanError); message != "" {
		return message
	}
	return listAllOperationalStatus(result.FeedStatus)
}

var listAllFindingSectionDefs = []struct {
	label string
	title string
	class string
}{
	{"Malicious", "Malicious", "s-mal"},
	{"Supply-chain", "Supply-Chain / EOL", "s-sce"},
	{"Vulnerability", "Vulnerabilities", "s-vuln"},
	{"Lifecycle", "Lifecycle Findings", "s-life"},
	{"Reputation info", "Reputation info", "s-life"},
}

func listAllFindingSections(rows []listAllFindingRow) []listAllFindingSection {
	if len(rows) == 0 {
		return nil
	}
	byType := make(map[string][]listAllFindingRow)
	knownTypes := make(map[string]struct{}, len(listAllFindingSectionDefs))
	for _, def := range listAllFindingSectionDefs {
		knownTypes[def.label] = struct{}{}
	}
	var other []listAllFindingRow
	for _, row := range rows {
		label := strings.TrimSpace(row.Type)
		if label == "" {
			other = append(other, row)
			continue
		}
		if _, ok := knownTypes[label]; !ok {
			other = append(other, row)
			continue
		}
		byType[label] = append(byType[label], row)
	}

	sections := make([]listAllFindingSection, 0, len(listAllFindingSectionDefs)+1)
	for _, def := range listAllFindingSectionDefs {
		findings := byType[def.label]
		if len(findings) == 0 {
			continue
		}
		sortListAllFindingRows(findings)
		sections = append(sections, listAllFindingSection{
			Title:     def.title,
			Class:     def.class,
			AriaLabel: def.title + " security findings table",
			Findings:  findings,
		})
	}
	if len(other) > 0 {
		sortListAllFindingRows(other)
		sections = append(sections, listAllFindingSection{
			Title:     "Other findings",
			Class:     "s-other",
			AriaLabel: "Other findings security findings table",
			Findings:  other,
		})
	}
	return sections
}

func sortListAllFindingRows(rows []listAllFindingRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		left := domain.Severity(rows[i].Severity).Rank()
		right := domain.Severity(rows[j].Severity).Rank()
		if left != right {
			return left > right
		}
		return rows[i].Package < rows[j].Package
	})
}

func listAllFindingTypeLabel(f domain.Finding) string {
	if domain.FindingIsInformational(f) {
		return "Reputation info"
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "Malicious"
	case domain.FindingTypeSupplyChainRisk:
		return "Supply-chain"
	case domain.FindingTypeVulnerability:
		return "Vulnerability"
	case domain.FindingTypeLifecycle:
		return "Lifecycle"
	default:
		return strings.TrimSpace(string(f.Type))
	}
}

func listAllFindingPackageLabel(f domain.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name != "" {
		return name
	}
	version := strings.TrimSpace(f.Version)
	if version != "" {
		return version
	}
	return "-"
}

func listAllFindingRiskType(f domain.Finding) string {
	if risk := strings.TrimSpace(f.RiskType); risk != "" {
		return listAllRiskTypeLabel(risk)
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return listAllRiskTypeLabel("malware")
	case domain.FindingTypeVulnerability:
		return listAllRiskTypeLabel("known_vulnerability")
	case domain.FindingTypeLifecycle:
		return listAllRiskTypeLabel("lifecycle")
	case domain.FindingTypeSupplyChainRisk:
		return listAllRiskTypeLabel("supply_chain")
	default:
		return "-"
	}
}

func listAllRiskTypeLabel(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "":
		return "-"
	case "known_vulnerability":
		return "Known vulnerability"
	case "malware":
		return "Malware"
	case domain.RiskTypeMalwareHistory:
		return "Malware history"
	case "removed_package":
		return "Removed package"
	case "supply_chain":
		return "Supply-chain risk"
	case "lifecycle":
		return "Lifecycle"
	case "eol":
		return "End-of-life"
	case "eol_soon":
		return "End-of-life soon"
	case "security_support_only":
		return "Security support only"
	case "security_support_ended":
		return "Security support ended"
	case "protestware":
		return "Protestware"
	case "typosquatting":
		return "Typosquatting"
	case "other":
		return "Other"
	default:
		return humanizeListAllToken(risk)
	}
}

func humanizeListAllToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '-'
	})
	if len(parts) == 0 {
		return value
	}
	for i, part := range parts {
		part = strings.ToLower(part)
		if part == "" {
			continue
		}
		if i == 0 {
			part = strings.ToUpper(part[:1]) + part[1:]
		}
		parts[i] = part
	}
	return strings.Join(parts, " ")
}

func listAllFindingTitle(f domain.Finding) string {
	if strings.EqualFold(strings.TrimSpace(f.RiskType), domain.RiskTypeMalwareHistory) {
		return "ReversingLabs: malware incident history"
	}
	return f.Title
}

func listAllAdvisoryLabel(f domain.Finding) string {
	return findinglinks.AdvisoryLabel(f)
}

func listAllAdvisoryURL(f domain.Finding) string {
	return findinglinks.AdvisoryURL(f)
}
