package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

const (
	maxPackageDetailNameLength    = 512
	maxPackageDetailVersionLength = 256
	packageDetailFindingLimit     = 20
)

// PackageData is the view model for the package detail template.
type PackageData struct {
	ActiveNav                string
	Ecosystem                string
	Name                     string
	Version                  string
	ReturnTo                 string
	ReturnToFallback         string
	Vulnerabilities          []PackageFinding
	VulnerabilitiesTotal     int
	VulnerabilitiesHidden    int
	VulnerabilitiesLoadError string
	Malicious                []PackageFinding
	MaliciousTotal           int
	MaliciousHidden          int
	MaliciousLoadError       string
	SupplyChain              []PackageFinding
	SupplyChainTotal         int
	SupplyChainHidden        int
	ReputationLoadError      string
	Lifecycle                []PackageFinding
	LifecycleTotal           int
	LifecycleHidden          int
	LifecycleLoadError       string
	Sources                  []string
	RiskTypeDefinitions      []RiskTypeDefinition
}

// PackageFinding is the package detail finding view model.
type PackageFinding struct {
	domain.Finding
}

// RiskTypeDefinition explains a machine risk_type code in the package detail UI.
type RiskTypeDefinition struct {
	Code        string
	Label       string
	Description string
}

var knownPackageRiskTypeDefinitions = []RiskTypeDefinition{
	{
		Code:        "vulnerability",
		Label:       "Vulnerability",
		Description: "Known vulnerability finding from a vulnerability feed.",
	},
	{
		Code:        "malicious",
		Label:       "Malicious package",
		Description: "Confirmed malicious package or release. Malicious package findings always block scans.",
	},
	{
		Code:        "malware",
		Label:       "Malicious package",
		Description: "Confirmed malicious package or release. Malware findings always block scans.",
	},
	{
		Code:        "removed_package",
		Label:       "Removed package",
		Description: "Registry or reputation source reports the package or version was removed.",
	},
	{
		Code:        "malware_history",
		Label:       "Malware history",
		Description: "Package has prior malware or reputation incidents and needs extra review.",
	},
	{
		Code:        "eol",
		Label:       "End-of-life",
		Description: "Release line is end of life and no longer receives fixes.",
	},
	{
		Code:        "eol_soon",
		Label:       "End-of-life soon",
		Description: "Release line is approaching end of life; plan an upgrade.",
	},
	{
		Code:        "security_support_only",
		Label:       "Security support only",
		Description: "Release line receives security fixes only; feature and bug fixes have ended.",
	},
	{
		Code:        "typosquatting",
		Label:       "Typosquatting",
		Description: "Package name resembles another package and may target dependency confusion.",
	},
	{
		Code:        "supply_chain",
		Label:       "Supply-chain risk",
		Description: "General supply-chain or package reputation signal from a feed.",
	},
}

// FallbackResourceLabel returns contextual link text when a finding has only a
// primary URL and no structured resource labels.
func (f PackageFinding) FallbackResourceLabel() string {
	return packageFindingFallbackResourceLabel(f.Finding)
}

// RiskTypeCode returns the raw machine risk_type code for debugging and exports.
func (f PackageFinding) RiskTypeCode() string {
	return strings.TrimSpace(f.RiskType)
}

// RiskTypeLabel returns a human-readable label for a known risk_type code.
func (f PackageFinding) RiskTypeLabel() string {
	if def, ok := packageRiskTypeDefinition(f.RiskType); ok {
		return def.Label
	}
	if code := normalizedPackageRiskTypeCode(f.RiskType); code != "" {
		return packageRiskTypeFallbackLabel(code)
	}
	return ""
}

// RiskTypeDescription returns compact help text for a risk_type code.
func (f PackageFinding) RiskTypeDescription() string {
	if def, ok := packageRiskTypeDefinition(f.RiskType); ok {
		return def.Description
	}
	if strings.TrimSpace(f.RiskType) != "" {
		return "Source-specific risk type not yet mapped by Packmon."
	}
	return ""
}

type packageFindings struct {
	vulnerabilities          []domain.Finding
	vulnerabilitiesLoadError string
	malicious                []domain.Finding
	maliciousLoadError       string
	supplyChain              []domain.Finding
	reputationLoadError      string
	lifecycle                []domain.Finding
	lifecycleLoadError       string
}

type packageLogContext struct {
	path           string
	nameLength     int
	versionPresent bool
	correlationID  string
}

// HandlePackage serves GET /package/{ecosystem}/{name...}.
// The {name...} wildcard captures the full remaining path, which is
// necessary for scoped package names like @scope/pkg or go module paths.
func HandlePackage(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ecosystem := strings.ToLower(strings.TrimSpace(r.PathValue("ecosystem")))
		name := r.PathValue("name")

		if ecosystem == "" || name == "" || len(name) > maxPackageDetailNameLength || !domain.Ecosystem(ecosystem).Valid() {
			renderNotFoundPage(w, r, renderer, logger, NotFoundData{ActiveNav: "search"}, "")
			return
		}

		ctx := r.Context()
		version := strings.TrimSpace(r.URL.Query().Get("version"))
		if len(version) > maxPackageDetailVersionLength {
			http.Error(w, webMessage(webMessageKey("package.error.version_too_long"), maxPackageDetailVersionLength), http.StatusBadRequest)
			return
		}
		returnToFallback := "/search"
		returnTo := validateSearchReturnTo(r.URL.Query().Get("return_to"))
		logCtx := newPackageLogContext(r, name, version)
		findings := loadPackageFindings(ctx, store, logger, logCtx, ecosystem, name, version)
		vulnerabilities, vulnerabilitiesTotal, vulnerabilitiesHidden := packageFindingDisplay(findings.vulnerabilities)
		malicious, maliciousTotal, maliciousHidden := packageFindingDisplay(findings.malicious)
		supplyChain, supplyChainTotal, supplyChainHidden := packageFindingDisplay(findings.supplyChain)
		lifecycle, lifecycleTotal, lifecycleHidden := packageFindingDisplay(findings.lifecycle)

		data := PackageData{
			ActiveNav:                "search",
			Ecosystem:                ecosystem,
			Name:                     name,
			Version:                  version,
			ReturnTo:                 returnTo,
			ReturnToFallback:         returnToFallback,
			Vulnerabilities:          vulnerabilities,
			VulnerabilitiesTotal:     vulnerabilitiesTotal,
			VulnerabilitiesHidden:    vulnerabilitiesHidden,
			VulnerabilitiesLoadError: findings.vulnerabilitiesLoadError,
			Malicious:                malicious,
			MaliciousTotal:           maliciousTotal,
			MaliciousHidden:          maliciousHidden,
			MaliciousLoadError:       findings.maliciousLoadError,
			SupplyChain:              supplyChain,
			SupplyChainTotal:         supplyChainTotal,
			SupplyChainHidden:        supplyChainHidden,
			ReputationLoadError:      findings.reputationLoadError,
			Lifecycle:                lifecycle,
			LifecycleTotal:           lifecycleTotal,
			LifecycleHidden:          lifecycleHidden,
			LifecycleLoadError:       findings.lifecycleLoadError,
			Sources:                  collectPackageSources(findings),
			RiskTypeDefinitions:      packageRiskTypeDefinitionsFor(findings),
		}

		if err := renderer.Render(w, "package.html", data); err != nil {
			logger.Error("package: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

func newPackageLogContext(r *http.Request, name, version string) packageLogContext {
	return packageLogContext{
		path:           logsafe.RequestPathLabel(r.URL.Path),
		nameLength:     len(name),
		versionPresent: version != "",
		correlationID:  requestctx.CorrelationIDFromContext(r.Context()),
	}
}

func packageLogArgs(logCtx packageLogContext, ecosystem string, err error) []any {
	attrs := []any{
		"ecosystem", ecosystem,
		"name_length", logCtx.nameLength,
		"version_present", logCtx.versionPresent,
		"path", logCtx.path,
		"error", err,
	}
	if logCtx.correlationID != "" {
		attrs = append(attrs, "correlation_id", logCtx.correlationID)
	}
	return attrs
}

func loadPackageFindings(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) packageFindings {
	var (
		vulnerabilities          []domain.Finding
		vulnerabilitiesLoadError string
		malicious                []domain.Finding
		maliciousLoadError       string
		reputationMalicious      []domain.Finding
		supplyChain              []domain.Finding
		reputationLoadError      string
		lifecycle                []domain.Finding
		lifecycleLoadError       string
		wg                       sync.WaitGroup
	)

	wg.Add(4)
	go func() {
		defer wg.Done()
		vulnerabilities, vulnerabilitiesLoadError = loadPackageVulnerabilities(ctx, store, logger, logCtx, ecosystem, name, version)
	}()
	go func() {
		defer wg.Done()
		malicious, maliciousLoadError = loadPackageMalicious(ctx, store, logger, logCtx, ecosystem, name, version)
	}()
	go func() {
		defer wg.Done()
		reputationMalicious, supplyChain, reputationLoadError = loadPackageReputation(ctx, store, logger, logCtx, ecosystem, name, version)
	}()
	go func() {
		defer wg.Done()
		lifecycle, lifecycleLoadError = loadPackageLifecycle(ctx, store, logger, logCtx, ecosystem, name, version)
	}()
	wg.Wait()

	return packageFindings{
		vulnerabilities:          vulnerabilities,
		vulnerabilitiesLoadError: vulnerabilitiesLoadError,
		malicious:                append(malicious, reputationMalicious...),
		maliciousLoadError:       maliciousLoadError,
		supplyChain:              supplyChain,
		reputationLoadError:      reputationLoadError,
		lifecycle:                lifecycle,
		lifecycleLoadError:       lifecycleLoadError,
	}
}

func loadPackageVulnerabilities(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) ([]domain.Finding, string) {
	vulnerabilities, err := store.FindVulnerabilities(ctx, ecosystem, name, version)
	if err != nil {
		logger.Error("package: failed to find vulnerabilities", packageLogArgs(logCtx, ecosystem, err)...)
		return vulnerabilities, webMessage(webMessageKey("package.error.vulnerabilities"))
	}
	return vulnerabilities, ""
}

func loadPackageMalicious(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) ([]domain.Finding, string) {
	malicious, err := store.FindMalicious(ctx, ecosystem, name, version)
	if err != nil {
		logger.Error("package: failed to find malicious findings", packageLogArgs(logCtx, ecosystem, err)...)
		return malicious, webMessage(webMessageKey("package.error.malicious"))
	}
	return malicious, ""
}

func loadPackageReputation(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) ([]domain.Finding, []domain.Finding, string) {
	reputation, loadError := findPackageReputation(ctx, store, logger, logCtx, ecosystem, name, version)
	if loadError != "" {
		return nil, []domain.Finding{}, loadError
	}

	malicious := []domain.Finding{}
	supplyChain := []domain.Finding{}
	for _, finding := range reputation {
		if finding.Type == domain.FindingTypeSupplyChainRisk {
			supplyChain = append(supplyChain, finding)
		} else {
			malicious = append(malicious, finding)
		}
	}
	return malicious, supplyChain, ""
}

func findPackageReputation(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) ([]domain.Finding, string) {
	sources := db.ReputationReadSources()
	reputation := make([]domain.Finding, 0)
	if version != "" {
		for _, source := range sources {
			findings, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, source.Source)
			if err != nil {
				logger.Error("package: failed to find reputation findings", packageLogArgs(logCtx, ecosystem, err)...)
				return reputation, webMessage(webMessageKey("package.error.reputation"))
			}
			reputation = append(reputation, findings...)
		}
		return reputation, ""
	}

	for _, source := range sources {
		findings, err := store.FindReputationFindings(ctx, ecosystem, name, source.Source)
		if err != nil {
			logger.Error("package: failed to find reputation findings", packageLogArgs(logCtx, ecosystem, err)...)
			return reputation, webMessage(webMessageKey("package.error.reputation"))
		}
		reputation = append(reputation, findings...)
	}
	return reputation, ""
}

func loadPackageLifecycle(ctx context.Context, store Store, logger *slog.Logger, logCtx packageLogContext, ecosystem, name, version string) ([]domain.Finding, string) {
	lifecycle := []domain.Finding{}
	if version == "" {
		return lifecycle, ""
	}

	lifecycle, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   version,
	}}, time.Now().UTC())
	if err != nil {
		logger.Error("package: failed to find lifecycle findings", packageLogArgs(logCtx, ecosystem, err)...)
		return lifecycle, webMessage(webMessageKey("package.error.lifecycle"))
	}
	return lifecycle, ""
}

func packageFindingDisplay(findings []domain.Finding) ([]PackageFinding, int, int) {
	total := len(findings)
	if total > packageDetailFindingLimit {
		findings = findings[:packageDetailFindingLimit]
	}
	return packageFindingViews(findings), total, total - len(findings)
}

func packageFindingViews(findings []domain.Finding) []PackageFinding {
	if len(findings) == 0 {
		return nil
	}
	views := make([]PackageFinding, 0, len(findings))
	for _, finding := range findings {
		views = append(views, PackageFinding{Finding: finding})
	}
	return views
}

func packageRiskTypeDefinition(raw string) (RiskTypeDefinition, bool) {
	code := normalizedPackageRiskTypeCode(raw)
	if code == "" {
		return RiskTypeDefinition{}, false
	}
	for _, def := range knownPackageRiskTypeDefinitions {
		if code == def.Code {
			return def, true
		}
	}
	return RiskTypeDefinition{}, false
}

func normalizedPackageRiskTypeCode(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func packageRiskTypeFallbackLabel(code string) string {
	parts := strings.FieldsFunc(code, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(parts) == 0 {
		return "Source-specific risk"
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

func packageRiskTypeDefinitionsFor(findings packageFindings) []RiskTypeDefinition {
	seen := make(map[string]struct{})
	add := func(items []domain.Finding) {
		for _, finding := range items {
			if def, ok := packageRiskTypeDefinition(finding.RiskType); ok {
				seen[def.Code] = struct{}{}
				continue
			}
			if code := normalizedPackageRiskTypeCode(finding.RiskType); code != "" {
				seen[code] = struct{}{}
			}
		}
	}
	add(findings.vulnerabilities)
	add(findings.malicious)
	add(findings.supplyChain)
	add(findings.lifecycle)
	if len(seen) == 0 {
		return nil
	}

	defs := make([]RiskTypeDefinition, 0, len(seen))
	for _, def := range knownPackageRiskTypeDefinitions {
		if _, ok := seen[def.Code]; ok {
			defs = append(defs, def)
			delete(seen, def.Code)
		}
	}
	unknownCodes := make([]string, 0, len(seen))
	for code := range seen {
		unknownCodes = append(unknownCodes, code)
	}
	sortStrings(unknownCodes)
	for _, code := range unknownCodes {
		defs = append(defs, RiskTypeDefinition{
			Code:        code,
			Label:       packageRiskTypeFallbackLabel(code),
			Description: "Source-specific risk type not yet mapped by Packmon.",
		})
	}
	return defs
}

func packageFindingFallbackResourceLabel(f domain.Finding) string {
	if advisorySource := packageFindingAdvisorySourceLabel(f.AdvisoryID); advisorySource != "" {
		return advisorySource + " advisory"
	}

	source := packageFindingSourceLabel(f.Source)
	target := packageFindingURLTargetLabel(f.URL)

	switch f.Type {
	case domain.FindingTypeMalicious:
		if source != "" {
			return source + " malware report"
		}
		if target != "" {
			return target + " malware report"
		}
		return "Malware report"
	case domain.FindingTypeSupplyChainRisk:
		if label, ok := db.ReputationReadSourceLabel(f.Source); ok {
			return label + " reputation report"
		}
		if strings.EqualFold(strings.TrimSpace(f.RiskType), "malware_history") {
			if source != "" {
				return source + " malware history report"
			}
			if target != "" {
				return target + " malware history report"
			}
			return "Malware history report"
		}
		if source != "" {
			return source + " supply-chain report"
		}
		if target != "" {
			return target + " supply-chain report"
		}
		return "Supply-chain risk report"
	case domain.FindingTypeLifecycle:
		if source != "" {
			return source + " lifecycle report"
		}
		if target != "" {
			return target + " lifecycle report"
		}
		return "Lifecycle report"
	case domain.FindingTypeVulnerability:
		if source != "" {
			return source + " advisory"
		}
		if target != "" {
			return target + " advisory"
		}
	}

	if source != "" {
		return source + " advisory"
	}
	if target != "" {
		return target + " advisory"
	}
	return "Finding advisory"
}

func packageFindingAdvisorySourceLabel(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(id, "CVE-"):
		return "NVD"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "RustSec"
	default:
		return ""
	}
}

func packageFindingURLTargetLabel(rawURL string) string {
	link := findinglinks.ResourceLinkFromURL(rawURL)
	return strings.TrimSpace(link.Label)
}

func packageFindingSourceLabel(source string) string {
	source = strings.TrimSpace(source)
	if label, ok := db.ReputationReadSourceLabel(source); ok {
		return label
	}
	switch strings.ToLower(source) {
	case "":
		return ""
	case "ghsa":
		return "GHSA"
	case "osv":
		return "OSV"
	case "nvd":
		return "NVD"
	case "vulncheck":
		return "VulnCheck"
	case "openssf":
		return "OpenSSF"
	case "socket", "socket.dev":
		return "Socket.dev"
	case "endoflife.date":
		return "endoflife.date"
	case domain.ManualAdvisorySource:
		return "Manual"
	default:
		return source
	}
}

func collectPackageSources(findings packageFindings) []string {
	sourceSet := make(map[string]struct{})
	addFindingSources(sourceSet, findings.vulnerabilities)
	addFindingSources(sourceSet, findings.malicious)
	addFindingSources(sourceSet, findings.supplyChain)
	addFindingSources(sourceSet, findings.lifecycle)

	sources := make([]string, 0, len(sourceSet))
	for source := range sourceSet {
		sources = append(sources, source)
	}
	sortStrings(sources)
	return sources
}

func addFindingSources(sourceSet map[string]struct{}, findings []domain.Finding) {
	for _, finding := range findings {
		sourceSet[finding.Source] = struct{}{}
	}
}

// sortStrings sorts a string slice in place using insertion sort.
// This avoids importing sort for a small slice.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && strings.Compare(s[j], key) > 0 {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
