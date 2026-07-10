// Package web provides the HTML-based web interface for the Packmon server.
// All templates are loaded from an embedded filesystem and rendered using
// Go's html/template package. HTMX handles client-side interactivity;
// Tailwind CSS is built into a local static asset.
package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/plural"
)

// Renderer loads, caches, and executes HTML templates from an embedded FS.
type Renderer struct {
	fs    fs.FS
	mu    sync.RWMutex
	cache map[string]*template.Template
	funcs template.FuncMap
	dev   bool // when true, templates are reloaded on every render
}

const staticAssetVersionLength = 16

// LayoutLinks are optional operator-facing links rendered by the shared layout.
type LayoutLinks struct {
	PrivacyURL string
	LegalURL   string
	TermsURL   string
	HideAdmin  bool
}

// NewRendererWithLayoutLinks creates a Renderer with shared footer notice links.
func NewRendererWithLayoutLinks(fsys fs.FS, dev bool, links LayoutLinks) *Renderer {
	links.PrivacyURL = strings.TrimSpace(links.PrivacyURL)
	links.LegalURL = strings.TrimSpace(links.LegalURL)
	links.TermsURL = strings.TrimSpace(links.TermsURL)
	assets := newStaticAssetVersions(fsys)
	return &Renderer{
		fs:    fsys,
		cache: make(map[string]*template.Template),
		funcs: defaultFuncMapWithAssets(links, assets),
		dev:   dev,
	}
}

// Render executes the named template, writing the result to w.
// The name must correspond to a file inside the templates/ directory,
// e.g. "dashboard.html" or "admin/login.html".
func (r *Renderer) Render(w io.Writer, name string, data any) error {
	t, err := r.load(name)
	if err != nil {
		return fmt.Errorf("render %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		return err
	}
	_, err = io.Copy(w, &buf)
	return err
}

// RenderPartial executes the named template without the layout wrapper.
// This is used for HTMX partial responses (hx-swap fragments).
func (r *Renderer) RenderPartial(w io.Writer, name, block string, data any) error {
	t, err := r.load(name)
	if err != nil {
		return fmt.Errorf("render partial %s/%s: %w", name, block, err)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, block, data); err != nil {
		return err
	}
	_, err = io.Copy(w, &buf)
	return err
}

// load returns a compiled template, using the cache unless dev mode is on.
func (r *Renderer) load(name string) (*template.Template, error) {
	if !r.dev {
		r.mu.RLock()
		if t, ok := r.cache[name]; ok {
			r.mu.RUnlock()
			return t, nil
		}
		r.mu.RUnlock()
	}

	t, err := r.parse(name)
	if err != nil {
		return nil, err
	}

	if !r.dev {
		r.mu.Lock()
		r.cache[name] = t
		r.mu.Unlock()
	}

	return t, nil
}

// parse reads the layout and the page template from the embedded FS and
// compiles them into a single template set.
func (r *Renderer) parse(name string) (*template.Template, error) {
	// Always start with the base layout.
	assetNeeds := layoutAssetNeeds{}
	funcs := copyTemplateFuncMap(r.funcs)
	funcs["layoutNeedsHTMX"] = func() bool { return assetNeeds.HTMX }
	funcs["layoutNeedsHelperScript"] = func() bool { return assetNeeds.HelperScript }
	t := template.New("").Funcs(funcs)

	layoutBytes, err := fs.ReadFile(r.fs, "templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("read layout: %w", err)
	}
	if _, err := t.Parse(string(layoutBytes)); err != nil {
		return nil, fmt.Errorf("parse layout: %w", err)
	}

	// Parse all partials.
	partials, _ := fs.Glob(r.fs, "templates/partials/*.html")
	for _, p := range partials {
		b, err := fs.ReadFile(r.fs, p)
		if err != nil {
			return nil, fmt.Errorf("read partial %s: %w", p, err)
		}
		if _, err := t.Parse(string(b)); err != nil {
			return nil, fmt.Errorf("parse partial %s: %w", p, err)
		}
	}

	// Parse the page template itself.
	pageBytes, err := fs.ReadFile(r.fs, "templates/"+name)
	if err != nil {
		return nil, fmt.Errorf("read page %s: %w", name, err)
	}
	assetNeeds = detectLayoutAssetNeeds(string(pageBytes))
	if _, err := t.Parse(string(pageBytes)); err != nil {
		return nil, fmt.Errorf("parse page %s: %w", name, err)
	}

	return t, nil
}

type layoutAssetNeeds struct {
	HTMX         bool
	HelperScript bool
}

func copyTemplateFuncMap(funcs template.FuncMap) template.FuncMap {
	copied := make(template.FuncMap, len(funcs)+2)
	for name, fn := range funcs {
		copied[name] = fn
	}
	return copied
}

func detectLayoutAssetNeeds(templateSource string) layoutAssetNeeds {
	needsHTMX := strings.Contains(templateSource, "hx-") || strings.Contains(templateSource, "data-hx-")
	needsHelper := false
	for _, marker := range []string{
		"admin-flash-alerts",
		"data-alert-dismiss",
		"data-auto-refresh-",
		"data-copy-target",
		"data-feed-sync-now",
		"data-preserve-scroll",
		"data-required-when-checked",
		"data-select-on-focus",
		"data-submit-lock",
	} {
		if strings.Contains(templateSource, marker) {
			needsHelper = true
			break
		}
	}
	if !needsHelper && needsHTMX && strings.Contains(templateSource, "aria-busy=") {
		needsHelper = true
	}
	return layoutAssetNeeds{HTMX: needsHTMX, HelperScript: needsHelper}
}

// defaultFuncMap returns the template functions available to every template.
func defaultFuncMap(links LayoutLinks) template.FuncMap {
	return defaultFuncMapWithAssets(links, newStaticAssetVersions(content))
}

func defaultFuncMapWithAssets(links LayoutLinks, assets *staticAssetVersions) template.FuncMap {
	if assets == nil {
		assets = newStaticAssetVersions(content)
	}
	return template.FuncMap{
		"formatTime":              formatTime,
		"formatTimeAgo":           formatTimeAgo,
		"formatTimeISO":           formatTimeISO,
		"formatFixedIn":           formatFixedIn,
		"severityClass":           severityClass,
		"statusClass":             statusClass,
		"feedModeLabel":           feedModeLabel,
		"truncate":                truncate,
		"findingLabels":           findingTypeLabels,
		"lower":                   strings.ToLower,
		"upper":                   strings.ToUpper,
		"hasPrefix":               strings.HasPrefix,
		"advisoryURL":             advisoryURL,
		"adminPrimaryButtonClass": adminPrimaryButtonClass,
		"dict":                    dict,
		"adminAlert":              adminAlertViewFor,
		"newTabAriaLabel":         newTabAriaLabel,
		"newTabSRText":            newTabSRText,
		"t":                       templateMessage,
		"count":                   plural.Count,
		"word":                    plural.Word,
		"add":                     func(a, b int) int { return a + b },
		"sub":                     func(a, b int) int { return a - b },
		"seq":                     seq,
		"privacyURL":              func() string { return links.PrivacyURL },
		"legalURL":                func() string { return links.LegalURL },
		"termsURL":                func() string { return links.TermsURL },
		"layoutDir":               layoutDir,
		"assetURL":                assets.URL,
		"layoutNeedsHTMX": func() bool {
			return false
		},
		"layoutNeedsHelperScript": func() bool {
			return false
		},
		"adminNavEnabled": func() bool {
			return !links.HideAdmin
		},
	}
}

func adminPrimaryButtonClass(extra ...string) string {
	return joinClassTokens(
		"inline-flex min-h-11 items-center justify-center rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:bg-accent-hover active:bg-accent-hover pm-focus-ring",
		strings.Join(extra, " "),
	)
}

func joinClassTokens(groups ...string) string {
	fields := make([]string, 0, len(groups))
	for _, group := range groups {
		fields = append(fields, strings.Fields(group)...)
	}
	return strings.Join(fields, " ")
}

type staticAssetVersions struct {
	fs    fs.FS
	mu    sync.RWMutex
	cache map[string]string
}

func newStaticAssetVersions(fsys fs.FS) *staticAssetVersions {
	return &staticAssetVersions{
		fs:    fsys,
		cache: make(map[string]string),
	}
}

func (v *staticAssetVersions) URL(assetPath string) string {
	fsPath, ok := normalizeStaticAssetFSPath(assetPath)
	if !ok {
		return assetPath
	}
	publicPath := "/" + fsPath
	version := v.version(fsPath)
	if version == "" {
		return publicPath
	}
	return publicPath + "?v=" + version
}

func (v *staticAssetVersions) matches(assetPath, version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	fsPath, ok := normalizeStaticAssetFSPath(assetPath)
	return ok && version == v.version(fsPath)
}

func (v *staticAssetVersions) version(assetPath string) string {
	if v == nil {
		return ""
	}
	fsPath, ok := normalizeStaticAssetFSPath(assetPath)
	if !ok {
		return ""
	}

	v.mu.RLock()
	version, ok := v.cache[fsPath]
	v.mu.RUnlock()
	if ok {
		return version
	}

	data, err := fs.ReadFile(v.fs, fsPath)
	if err == nil {
		sum := sha256.Sum256(data)
		version = hex.EncodeToString(sum[:])[:staticAssetVersionLength]
	}

	v.mu.Lock()
	if cached, ok := v.cache[fsPath]; ok {
		v.mu.Unlock()
		return cached
	}
	v.cache[fsPath] = version
	v.mu.Unlock()
	return version
}

func normalizeStaticAssetFSPath(assetPath string) (string, bool) {
	raw := strings.TrimSpace(assetPath)
	if raw == "" || strings.Contains(raw, "\\") {
		return "", false
	}
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", false
	}
	hasStaticPrefix := strings.HasPrefix(raw, "static/")
	clean := path.Clean(raw)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	if hasStaticPrefix {
		if !strings.HasPrefix(clean, "static/") {
			return "", false
		}
	} else {
		clean = path.Join("static", clean)
	}
	if clean == "static" || !strings.HasPrefix(clean, "static/") || !fs.ValidPath(clean) {
		return "", false
	}
	return clean, true
}

func layoutDir(data any) string {
	dir := strings.ToLower(strings.TrimSpace(layoutDirValue(data)))
	switch dir {
	case "ltr", "rtl", "auto":
		return dir
	default:
		return "ltr"
	}
}

func layoutDirValue(data any) string {
	if data == nil {
		return ""
	}
	v := reflect.ValueOf(data)
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return ""
		}
		key := reflect.ValueOf("LayoutDir").Convert(v.Type().Key())
		value := v.MapIndex(key)
		if !value.IsValid() {
			return ""
		}
		for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return ""
			}
			value = value.Elem()
		}
		if value.Kind() == reflect.String {
			return value.String()
		}
	case reflect.Struct:
		value := v.FieldByName("LayoutDir")
		if value.IsValid() && value.Kind() == reflect.String {
			return value.String()
		}
	}
	return ""
}

func feedModeLabel(mode any) string {
	if mode == nil {
		return "Unknown"
	}
	token := strings.ToLower(strings.TrimSpace(fmt.Sprint(mode)))
	switch token {
	case "self":
		return "Self-managed"
	case "external":
		return "External"
	case "":
		return "Unknown"
	default:
		return readableTokenLabel(token)
	}
}

func readableTokenLabel(token string) string {
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(parts) == 0 {
		return "Unknown"
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

type adminAlertView struct {
	Variant        string
	Icon           bool
	Live           bool
	Dismissible    bool
	Role           string
	AriaLive       string
	ContainerClass string
	IconClass      string
	Success        bool
	Error          bool
	Warning        bool
	Info           bool
}

func adminAlertViewFor(data any) adminAlertView {
	variant := strings.ToLower(strings.TrimSpace(adminAlertStringValue(data, "Variant")))
	if variant == "" {
		variant = "default"
	}
	alert := adminAlertView{
		Variant:     variant,
		Icon:        adminAlertBoolValue(data, "Icon"),
		Live:        adminAlertBoolValue(data, "Live"),
		Dismissible: adminAlertBoolValue(data, "Dismissible"),
	}
	if alert.Live {
		alert.Role = "status"
		alert.AriaLive = "polite"
		if variant == "error" {
			alert.Role = "alert"
			alert.AriaLive = "assertive"
		}
	}

	switch variant {
	case "success":
		alert.ContainerClass = "pm-alert-success"
		alert.IconClass = "pm-alert-icon-success"
		alert.Success = true
	case "error":
		alert.ContainerClass = "pm-alert-error"
		alert.IconClass = "pm-alert-icon-error"
		alert.Error = true
	case "warning":
		alert.ContainerClass = "pm-alert-warning"
		alert.IconClass = "pm-alert-icon-warning"
		alert.Warning = true
	case "info":
		alert.ContainerClass = "pm-alert-info"
		alert.IconClass = "pm-alert-icon-info"
		alert.Info = true
	default:
		alert.ContainerClass = "pm-alert-default"
		alert.IconClass = "pm-alert-icon-default"
	}
	return alert
}

func adminAlertStringValue(data any, key string) string {
	value := adminAlertValue(data, key)
	if !value.IsValid() {
		return ""
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.Kind() == reflect.String {
		return value.String()
	}
	return ""
}

func adminAlertBoolValue(data any, key string) bool {
	value := adminAlertValue(data, key)
	if !value.IsValid() {
		return false
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	return value.Kind() == reflect.Bool && value.Bool()
}

func adminAlertValue(data any, key string) reflect.Value {
	if data == nil {
		return reflect.Value{}
	}
	value := reflect.ValueOf(data)
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return reflect.Value{}
		}
		mapKey := reflect.ValueOf(key).Convert(value.Type().Key())
		return value.MapIndex(mapKey)
	case reflect.Struct:
		field := value.FieldByName(key)
		if field.IsValid() && field.CanInterface() {
			return field
		}
	}
	return reflect.Value{}
}

func dict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict requires an even number of arguments")
	}
	out := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		out[key] = values[i+1]
	}
	return out, nil
}

func advisoryURL(id string) string {
	link, _, ok := findinglinks.CanonicalVulnerabilityResource(strings.TrimSpace(id))
	if !ok {
		return ""
	}
	return link.URL
}

// formatTime renders a time.Time as a human-readable string.
// Returns "-" for zero times.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func formatTimeISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// formatTimeAgo renders a time.Time as a relative "X ago" string.
func formatTimeAgo(t time.Time) string {
	return formatTimeAgoAt(t, time.Now())
}

type webMessageKey string

const (
	webMessageNever              webMessageKey = "time.never"
	webMessageJustNow            webMessageKey = "time.just_now"
	webMessageMinuteAgoOne       webMessageKey = "time.minute_ago.one"
	webMessageMinuteAgoOther     webMessageKey = "time.minute_ago.other"
	webMessageHourAgoOne         webMessageKey = "time.hour_ago.one"
	webMessageHourAgoOther       webMessageKey = "time.hour_ago.other"
	webMessageDayAgoOne          webMessageKey = "time.day_ago.one"
	webMessageDayAgoOther        webMessageKey = "time.day_ago.other"
	webMessageLessThanMinute     webMessageKey = "time.in_less_than_minute"
	webMessageMinuteFutureOne    webMessageKey = "time.minute_future.one"
	webMessageMinuteFutureOther  webMessageKey = "time.minute_future.other"
	webMessageHourFutureOne      webMessageKey = "time.hour_future.one"
	webMessageHourFutureOther    webMessageKey = "time.hour_future.other"
	webMessageDayFutureOne       webMessageKey = "time.day_future.one"
	webMessageDayFutureOther     webMessageKey = "time.day_future.other"
	webMessageNewTabAriaLabel    webMessageKey = "link.new_tab.aria_label"
	webMessageNewTabScreenReader webMessageKey = "link.new_tab.screen_reader"
)

var webMessagesEN = map[webMessageKey]string{
	webMessageNever:                                                     "never",
	webMessageJustNow:                                                   "just now",
	webMessageMinuteAgoOne:                                              "1 minute ago",
	webMessageMinuteAgoOther:                                            "%d minutes ago",
	webMessageHourAgoOne:                                                "1 hour ago",
	webMessageHourAgoOther:                                              "%d hours ago",
	webMessageDayAgoOne:                                                 "1 day ago",
	webMessageDayAgoOther:                                               "%d days ago",
	webMessageLessThanMinute:                                            "in less than a minute",
	webMessageMinuteFutureOne:                                           "in 1 minute",
	webMessageMinuteFutureOther:                                         "in %d minutes",
	webMessageHourFutureOne:                                             "in 1 hour",
	webMessageHourFutureOther:                                           "in %d hours",
	webMessageDayFutureOne:                                              "in 1 day",
	webMessageDayFutureOther:                                            "in %d days",
	webMessageNewTabAriaLabel:                                           "%s opens in a new tab",
	webMessageNewTabScreenReader:                                        " (opens in a new tab)",
	webMessageKey("a11y.skip_to_main"):                                  "Skip to main content",
	webMessageKey("nav.primary"):                                        "Primary",
	webMessageKey("nav.dashboard"):                                      "Dashboard",
	webMessageKey("nav.search"):                                         "Search",
	webMessageKey("nav.feeds"):                                          "Feed Status",
	webMessageKey("nav.admin"):                                          "Admin",
	webMessageKey("theme.label"):                                        "Theme",
	webMessageKey("theme.light"):                                        "Light",
	webMessageKey("theme.dark"):                                         "Dark",
	webMessageKey("theme.system"):                                       "System",
	webMessageKey("footer.product"):                                     "Packmon Dependency Scanner",
	webMessageKey("footer.privacy"):                                     "Privacy",
	webMessageKey("footer.legal"):                                       "Legal Notice",
	webMessageKey("footer.terms"):                                       "Terms",
	webMessageKey("action.retry"):                                       "Retry",
	webMessageKey("page.search.title"):                                  "Packmon - Search",
	webMessageKey("search.heading"):                                     "Package Search",
	webMessageKey("search.input.label"):                                 "Search packages by name",
	webMessageKey("search.input.placeholder"):                           "e.g. lodash, requests, express...",
	webMessageKey("search.severity.label"):                              "Severity Filter",
	webMessageKey("search.severity.all"):                                "All severities",
	webMessageKey("search.finding.label"):                               "Finding Type",
	webMessageKey("search.finding.all"):                                 "All findings",
	webMessageKey("search.finding.vulnerabilities"):                     "Vulnerabilities",
	webMessageKey("search.finding.malicious"):                           "Malicious packages",
	webMessageKey("search.finding.supply_chain"):                        "Supply-chain risks",
	webMessageKey("search.finding.lifecycle"):                           "Lifecycle",
	webMessageKey("search.help"):                                        "Search by package name, severity, finding type, or any combination of them.",
	webMessageKey("search.htmx.loading"):                                "Updating results...",
	webMessageKey("search.htmx.error"):                                  "Request failed. Showing the last loaded results.",
	webMessageKey("search.htmx.timeout"):                                "Request timed out. Showing the last loaded results.",
	webMessageKey("search.htmx.swap_error"):                             "Update failed. Showing the last loaded results.",
	webMessageKey("search.htmx.stale"):                                  "The last loaded results remain visible below.",
	webMessageKey("search.status.failed"):                               "Search failed.",
	webMessageKey("search.status.results_updated"):                      "%d package search %s updated.",
	webMessageKey("search.status.more_available"):                       "More results are available.",
	webMessageKey("search.status.empty_filters"):                        "No packages found for the current search and filters.",
	webMessageKey("search.status.ready"):                                "Search ready. Enter a package name or choose filters.",
	webMessageKey("search.summary.matches"):                             "Showing matches %d-%d",
	webMessageKey("search.summary.first_matches"):                       "Showing first %d matches",
	webMessageKey("search.table.label"):                                 "Package search results table",
	webMessageKey("search.table.package"):                               "Package",
	webMessageKey("search.table.ecosystem"):                             "Ecosystem",
	webMessageKey("search.table.findings"):                              "Findings",
	webMessageKey("search.table.finding_details"):                       "Finding details",
	webMessageKey("search.table.sources"):                               "Sources",
	webMessageKey("search.version.label"):                               "Version:",
	webMessageKey("search.detail.malicious"):                            "%d malicious package %s",
	webMessageKey("search.detail.supply_chain"):                         "%d supply-chain risk %s",
	webMessageKey("search.detail.lifecycle"):                            "%d lifecycle %s",
	webMessageKey("search.detail.vulnerability"):                        "%d vulnerability %s",
	webMessageKey("search.detail.non_vulnerability"):                    "%d non-vulnerability %s",
	webMessageKey("search.detail.no_matching"):                          "No matching findings",
	webMessageKey("search.pagination.end"):                              "End of results for this search.",
	webMessageKey("search.pagination.previous"):                         "Previous page",
	webMessageKey("search.pagination.next"):                             "Next page",
	webMessageKey("search.empty.current_filter"):                        "No packages found for the current search and filter.",
	webMessageKey("search.empty.initial"):                               "Enter a package name above or choose filters to search package security data.",
	webMessageKey("page.feeds.title"):                                   "Packmon - Feed Status",
	webMessageKey("feeds.heading"):                                      "Feed Status",
	webMessageKey("feeds.refresh.auto_label"):                           "Auto-refresh",
	webMessageKey("feeds.refresh.running"):                              "On (30s)",
	webMessageKey("feeds.refresh.paused"):                               "Paused",
	webMessageKey("feeds.refreshing"):                                   "Refreshing feed status...",
	webMessageKey("feeds.refresh.now_aria"):                             "Refresh status now",
	webMessageKey("feeds.refresh.now"):                                  "Refresh now",
	webMessageKey("feeds.htmx.success"):                                 "Feed status refreshed.",
	webMessageKey("feeds.htmx.error"):                                   "Request failed. Showing the last loaded feed status.",
	webMessageKey("feeds.htmx.timeout"):                                 "Request timed out. Showing the last loaded feed status.",
	webMessageKey("feeds.htmx.swap_error"):                              "Update failed. Showing the last loaded feed status.",
	webMessageKey("feeds.htmx.stale"):                                   "The last loaded feed status remains visible below.",
	webMessageKey("feeds.status.load_failed"):                           "Feed status could not be loaded.",
	webMessageKey("feeds.status.updated_count"):                         "Feed status updated. %s shown.",
	webMessageKey("feeds.status.updated_empty"):                         "Feed status updated. No feed sync data available.",
	webMessageKey("feeds.table.label"):                                  "Feed status table",
	webMessageKey("feeds.table.feed"):                                   "Feed",
	webMessageKey("feeds.table.status"):                                 "Status",
	webMessageKey("feeds.table.last_sync"):                              "Last Sync",
	webMessageKey("feeds.table.entries"):                                "Entries",
	webMessageKey("feeds.table.message"):                                "Message",
	webMessageKey("feeds.last_result"):                                  "Last result:",
	webMessageKey("feeds.empty"):                                        "No feed sync data available. Feeds may not have run yet.",
	webMessageKey("feeds.error.load_status"):                            "Feed status could not be loaded. Check the server logs and database connection before relying on feed health.",
	webMessageKey("page.dashboard.title"):                               "Packmon - Dashboard",
	webMessageKey("dashboard.card.packages"):                            "Packages Tracked",
	webMessageKey("dashboard.card.vulnerabilities"):                     "Vulnerabilities",
	webMessageKey("dashboard.card.malicious"):                           "Malicious Packages",
	webMessageKey("dashboard.card.supply_chain"):                        "Supply-chain Risks",
	webMessageKey("dashboard.card.lifecycle"):                           "Lifecycle Findings",
	webMessageKey("dashboard.card.scans_7d"):                            "Scans (7d)",
	webMessageKey("dashboard.card.feeds_healthy"):                       "Feeds Healthy",
	webMessageKey("dashboard.total_scans_7d"):                           "Total Scans (7d)",
	webMessageKey("dashboard.unavailable"):                              "unavailable",
	webMessageKey("dashboard.severity.heading"):                         "Findings by Severity",
	webMessageKey("dashboard.recent_vulnerabilities.heading"):           "Recently Published Vulnerabilities (7 Days)",
	webMessageKey("dashboard.recent_vulnerabilities.table"):             "Recently published vulnerabilities table",
	webMessageKey("dashboard.table.advisory"):                           "Advisory",
	webMessageKey("dashboard.table.package"):                            "Package",
	webMessageKey("dashboard.table.version"):                            "Version",
	webMessageKey("dashboard.table.ecosystem"):                          "Ecosystem",
	webMessageKey("dashboard.table.severity"):                           "Severity",
	webMessageKey("dashboard.table.summary"):                            "Summary",
	webMessageKey("dashboard.table.published"):                          "Published",
	webMessageKey("dashboard.advisory_label"):                           "%s advisory",
	webMessageKey("dashboard.package_details_aria"):                     "View package details for %s/%s",
	webMessageKey("dashboard.affected_label"):                           "Affected:",
	webMessageKey("dashboard.details_badge"):                            "Details",
	webMessageKey("dashboard.recent_vulnerabilities.empty"):             "No vulnerabilities were published in the last 7 days.",
	webMessageKey("dashboard.error.stats"):                              "Dashboard metrics could not be loaded. Check the server logs and database connection before relying on these totals.",
	webMessageKey("dashboard.error.scan_activity"):                      "Scan activity could not be loaded. Check the server logs and database connection before relying on recent scan counts.",
	webMessageKey("dashboard.error.recent_vulnerabilities"):             "Recent vulnerabilities could not be loaded. Check the server logs and database connection before relying on this section.",
	webMessageKey("page.package.title"):                                 "Packmon - %s/%s",
	webMessageKey("package.breadcrumb.label"):                           "Breadcrumb",
	webMessageKey("package.breadcrumb.search"):                          "Search",
	webMessageKey("package.version.label"):                              "Version",
	webMessageKey("package.version.placeholder"):                        "3.2.25",
	webMessageKey("package.action.check_version"):                       "Check version",
	webMessageKey("package.risk_reference.heading"):                     "Risk type reference",
	webMessageKey("package.malicious.heading"):                          "Malicious Package Reports (%d)",
	webMessageKey("package.supply_chain.heading"):                       "Supply-chain Risks (%d)",
	webMessageKey("package.vulnerabilities.heading"):                    "Vulnerabilities (%d)",
	webMessageKey("package.lifecycle.heading"):                          "Lifecycle (%d)",
	webMessageKey("package.showing_first"):                              "Showing first %d of %d. %d more not shown.",
	webMessageKey("package.malicious.table"):                            "Malicious package reports table",
	webMessageKey("package.supply_chain.table"):                         "Supply-chain risk findings table",
	webMessageKey("package.vulnerability.table"):                        "Vulnerability findings table",
	webMessageKey("package.lifecycle.table"):                            "Lifecycle findings table",
	webMessageKey("package.table.severity"):                             "Severity",
	webMessageKey("package.table.advisory"):                             "Advisory",
	webMessageKey("package.table.version"):                              "Version",
	webMessageKey("package.table.risk_type"):                            "Risk Type",
	webMessageKey("package.table.title"):                                "Title",
	webMessageKey("package.table.resources"):                            "Resources",
	webMessageKey("package.table.fixed_version"):                        "Fixed Version",
	webMessageKey("package.table.source"):                               "Source",
	webMessageKey("package.empty.malicious"):                            "No malicious package reports for this package.",
	webMessageKey("package.empty.supply_chain"):                         "No supply-chain risk reports for this package.",
	webMessageKey("package.vulnerabilities.empty"):                      "No vulnerability findings for this package.",
	webMessageKey("package.lifecycle.empty_version"):                    "No lifecycle findings for this package version.",
	webMessageKey("package.lifecycle.empty_version_required"):           "Enter a version above to evaluate lifecycle status.",
	webMessageKey("package.error.version_too_long"):                     "package version exceeds %d characters",
	webMessageKey("package.error.vulnerabilities"):                      "Vulnerability findings could not be loaded. Check the server logs and database connection before relying on this section.",
	webMessageKey("package.error.malicious"):                            "Malicious package reports could not be loaded. Check the server logs and database connection before relying on this section.",
	webMessageKey("package.error.reputation"):                           "Reputation findings could not be loaded. Check the server logs and database connection before relying on malicious or supply-chain reputation sections.",
	webMessageKey("package.error.lifecycle"):                            "Lifecycle findings could not be loaded. Check the server logs and database connection before relying on this section.",
	webMessageKey("page.scans.title"):                                   "Packmon - Scans",
	webMessageKey("scans.heading"):                                      "Scans",
	webMessageKey("scans.activity.heading"):                             "Scan Activity (Last 7 Days)",
	webMessageKey("scans.activity.table"):                               "Scan activity table",
	webMessageKey("scans.table.date_utc"):                               "Date (UTC)",
	webMessageKey("scans.table.scans"):                                  "Scans",
	webMessageKey("scans.table.findings"):                               "Findings",
	webMessageKey("scans.table.relative_findings"):                      "Relative findings",
	webMessageKey("scans.relative_bar_label"):                           "%d %s; relative bar %d%% of the highest finding day in this table",
	webMessageKey("scans.relative_bar_local_label"):                     "%d %s; relative bar %%s of the highest finding day in this table",
	webMessageKey("scans.relative_bar_empty"):                           "0 findings; no relative findings bar",
	webMessageKey("scans.activity.empty"):                               "No scan activity in the last 7 days.",
	webMessageKey("scans.recent.heading"):                               "Recent Scans",
	webMessageKey("scans.recent.pages_label"):                           "Recent scans pages",
	webMessageKey("scans.recent.newer"):                                 "Newer scans",
	webMessageKey("scans.recent.older"):                                 "Older scans",
	webMessageKey("scans.recent.table"):                                 "Recent scans table",
	webMessageKey("scans.table.scan_id"):                                "Scan ID",
	webMessageKey("scans.table.time"):                                   "Time",
	webMessageKey("scans.table.packages"):                               "Packages",
	webMessageKey("scans.table.duration"):                               "Duration",
	webMessageKey("scans.recent.empty"):                                 "No scans recorded yet. Run",
	webMessageKey("scans.recent.empty_suffix"):                          "to get started.",
	webMessageKey("scans.error.activity"):                               "Scan activity could not be loaded. Check the server logs and database connection before relying on scan trend data.",
	webMessageKey("scans.error.recent"):                                 "Recent scans could not be loaded. Check the server logs and database connection before relying on scan history.",
	webMessageKey("page.privacy.title"):                                 "Packmon - Privacy Notice",
	webMessageKey("privacy.heading"):                                    "Privacy Notice",
	webMessageKey("privacy.last_updated"):                               "Last updated: 2026-06-29",
	webMessageKey("privacy.session.heading"):                            "Session cookie",
	webMessageKey("privacy.controller.heading"):                         "Controller and contact",
	webMessageKey("privacy.legal_basis.heading"):                        "Legal basis",
	webMessageKey("privacy.operational_metadata.heading"):               "Operational metadata",
	webMessageKey("privacy.data_categories.heading"):                    "Data categories, sources, purposes, and retention",
	webMessageKey("privacy.third_party.heading"):                        "Optional third-party feed recipients",
	webMessageKey("privacy.webhook.heading"):                            "Webhook recipients",
	webMessageKey("privacy.rights.heading"):                             "Rights and requests",
	webMessageKey("privacy.california.heading"):                         "California privacy rights",
	webMessageKey("privacy.operator_notice.heading"):                    "Operator notice",
	webMessageKey("privacy.session.body_intro"):                         "Packmon uses the first-party",
	webMessageKey("privacy.session.body_after_cookie"):                  "cookie for admin login sessions, login-form CSRF protection, and logout. The cookie is scoped to",
	webMessageKey("privacy.session.body_after_scope"):                   "is HttpOnly, and SameSite=Strict. Authenticated admin session cookies use the configured admin session lifetime as their absolute lifetime, while the server can invalidate inactive admin sessions earlier through the configured admin idle timeout. Login-form CSRF sessions are short-lived pre-authentication sessions and expire after at most 15 minutes.",
	webMessageKey("privacy.controller.body_intro"):                      "Packmon is intended for internal deployment. The organization operating this Packmon instance is the controller for deployment-specific personal data. Operators should publish controller, privacy contact, and data protection officer details through their own legal notice or by setting",
	webMessageKey("privacy.legal_basis.body"):                           "Depending on the deployment, processing can be based on legitimate interests in securing software supply chains, legal obligations for vulnerability management, contract or employment administration, and compliance with internal security policies. Operators must confirm and document the legal basis that applies to their environment.",
	webMessageKey("privacy.operational_metadata.audit"):                 "The server can store admin audit log entries for security-sensitive actions, including action names, timestamps, and client address metadata. Scan history and scan metadata can contain package names, versions, ecosystems, repository metadata supplied by clients, result counts, and operational errors needed to troubleshoot dependency-security decisions.",
	webMessageKey("privacy.operational_metadata.scan_logs"):             "Authenticated remote scan-log rows can contain scan time, bounded repository name, client IP, API key ID/name, correlation ID, package and finding counts, finding IDs and severities, feed status and versions, request and result digests, duration, block threshold, and the bounded Packmon client version. New scan-log rows do not retain branch, commit, or raw User-Agent values.",
	webMessageKey("privacy.operational_metadata.retention"):             "Operators should define purpose, access, retention, and employee-monitoring or works-council notices before using scan logs to review individual, runner, or team activity.",
	webMessageKey("privacy.data_categories.categories"):                 "The categories of personal information that can appear in Packmon metadata include Identifiers such as client IP addresses and API key labels, internet or network activity such as request timing and endpoint access, and commercial or employment-related operational metadata such as repository names, package coordinates, scan outcomes, and admin actions.",
	webMessageKey("privacy.data_categories.sources"):                    "These values are collected directly from admins, CI clients, CLI/API users, operator configuration, and Packmon-generated scan or audit events. Packmon uses them for business purposes such as authentication, dependency-security decisions, abuse prevention, audit evidence, troubleshooting, retention enforcement, and service operation.",
	webMessageKey("privacy.data_categories.retention"):                  "Default retention is deployment-controlled. Operators configure scan-log, admin-audit, refresh-queue, package-check, deleted-key, and cache retention settings and should align backups and exports with the same policy.",
	webMessageKey("privacy.third_party.body"):                           "Optional Socket.dev and ReversingLabs integrations are disabled unless configured by the operator. When enabled, queued package reputation lookups may send package coordinates such as ecosystem, package name, version, or package URL to the configured provider. Operators can suppress configured private namespaces from these lookups.",
	webMessageKey("privacy.webhook.body"):                               "Optional webhook delivery sends the canonical scan result payload to an operator-configured webhook recipient. The payload can include package names, versions, advisory and finding IDs, severities, parser diagnostics, feed status, and the repository name unless repository metadata is disabled.",
	webMessageKey("privacy.rights.body"):                                "Where GDPR or similar law applies, data subjects may have the right to access, right to erasure, right to rectification, right to data portability, right to object, and right to restrict processing. They may also have the right to complain to a supervisory authority. Operators are responsible for receiving and handling requests for their deployment.",
	webMessageKey("privacy.california.rights"):                          "For covered California deployments, CCPA/CPRA rights can include the right to know, right to delete, right to correct, right to opt out of sale or sharing, the right to limit use of sensitive personal information where applicable, and non-discrimination for exercising those rights.",
	webMessageKey("privacy.california.gpc"):                             "Packmon does not sell or share personal information by itself and does not use Global Privacy Control signals to change server behavior. Operators that sell, share, or combine Packmon metadata with other systems must provide their own Do Not Sell or Share mechanism and request method.",
	webMessageKey("privacy.operator_notice.body"):                       "Packmon is intended for internal deployment. Your organization controls retention, access, and any additional privacy or legal notices for its environment.",
	webMessageKey("privacy.legal_notice.prefix"):                        "See the configured",
	webMessageKey("privacy.legal_notice.suffix"):                        "for operator-specific information.",
	webMessageKey("privacy.legal_notice.link"):                          "Legal Notice",
	webMessageKey("admin.bootstrap.error.rotation_required"):            "Change the bootstrap password before making admin changes.",
	webMessageKey("admin.bootstrap.error.verify_password_state"):        "Failed to verify admin password state",
	webMessageKey("admin.form.error.invalid_request"):                   "Invalid request. Reload the page and try again.",
	webMessageKey("admin.form.error.invalid_payload"):                   "Invalid form payload. Reload the page and try again.",
	webMessageKey("page.admin.settings.title"):                          "Packmon - Admin Settings",
	webMessageKey("admin.settings.heading"):                             "System Settings",
	webMessageKey("admin.settings.runtime.heading"):                     "Runtime Policy",
	webMessageKey("admin.settings.runtime.description"):                 "Saved values apply immediately and are persisted for future server starts.",
	webMessageKey("admin.settings.status.unavailable"):                  "settings unavailable",
	webMessageKey("admin.settings.status.updated"):                      "updated",
	webMessageKey("admin.settings.status.database_override"):            "database override",
	webMessageKey("admin.settings.status.runtime_default"):              "runtime default",
	webMessageKey("admin.settings.system.locked_bootstrap"):             "Runtime policy changes are locked until the bootstrap password is changed below.",
	webMessageKey("admin.settings.system.saving"):                       "Saving system settings",
	webMessageKey("admin.settings.system.threshold_label"):              "Vulnerability Block Threshold",
	webMessageKey("admin.settings.system.threshold_none"):               "NONE - do not block vulnerabilities",
	webMessageKey("admin.settings.system.threshold_help"):               "Malicious package findings always block regardless of this threshold.",
	webMessageKey("admin.settings.system.runtime_value"):                "Runtime: %v",
	webMessageKey("admin.settings.system.rate_minute_label"):            "Rate Limit / Minute",
	webMessageKey("admin.settings.system.rate_minute_help"):             "Allowed range: 1-%d requests per minute.",
	webMessageKey("admin.settings.system.rate_burst_label"):             "Rate Limit Burst",
	webMessageKey("admin.settings.system.rate_burst_help"):              "Allowed range: 1-%d short-spike allowance requests.",
	webMessageKey("admin.settings.system.scan_retention"):               "Scan Log Retention",
	webMessageKey("admin.settings.system.scan_retention_help"):          "Days to keep scan-log metadata. 0 disables pruning.",
	webMessageKey("admin.settings.system.audit_retention"):              "Admin Audit Retention",
	webMessageKey("admin.settings.system.audit_retention_help"):         "Days to keep admin audit metadata. 0 disables pruning.",
	webMessageKey("admin.settings.system.runtime_days"):                 "Runtime: %v days",
	webMessageKey("admin.settings.system.none_required"):                "Acknowledge vulnerability blocking is disabled before saving NONE.",
	webMessageKey("admin.settings.system.none_warning"):                 "NONE disables vulnerability blocking. Malicious package findings and active supply-chain risk findings still block. This acknowledgement is required before saving NONE.",
	webMessageKey("admin.settings.system.save"):                         "Save System Settings",
	webMessageKey("admin.settings.password.heading"):                    "Change Admin Password",
	webMessageKey("admin.settings.password.changing"):                   "Changing password",
	webMessageKey("admin.settings.password.length_help"):                "Use at least %d characters.",
	webMessageKey("admin.settings.password.confirm_help"):               "The confirmation must match the new password.",
	webMessageKey("admin.settings.password.current_label"):              "Current Password",
	webMessageKey("admin.settings.password.new_label"):                  "New Password",
	webMessageKey("admin.settings.password.confirm_label"):              "Confirm New Password",
	webMessageKey("admin.settings.password.mismatch"):                   "New passwords do not match.",
	webMessageKey("admin.settings.password.change"):                     "Change Password",
	webMessageKey("admin.settings.server.heading"):                      "Server Information",
	webMessageKey("admin.settings.server.unavailable"):                  "unavailable",
	webMessageKey("admin.settings.error.auth_state"):                    "Admin account metadata could not be loaded.",
	webMessageKey("admin.settings.error.system_settings_load"):          "System settings could not be loaded. Reload after the database is healthy before saving policy changes.",
	webMessageKey("admin.settings.error.invalid_block_threshold"):       "Invalid block threshold",
	webMessageKey("admin.settings.error.block_threshold_none_ack"):      "Block threshold NONE requires explicit acknowledgement",
	webMessageKey("admin.settings.error.invalid_rate_limit_per_minute"): "Invalid rate limit per minute",
	webMessageKey("admin.settings.error.invalid_rate_limit_burst"):      "Invalid rate limit burst",
	webMessageKey("admin.settings.error.load_system_settings"):          "Failed to load system settings",
	webMessageKey("admin.settings.error.invalid_scan_log_retention"):    "Invalid scan log retention",
	webMessageKey("admin.settings.error.invalid_admin_audit_retention"): "Invalid admin audit retention",
	webMessageKey("admin.settings.error.invalid_revision"):              "Invalid system settings revision",
	webMessageKey("admin.settings.error.conflict"):                      "System settings changed while you were editing. Reload and try again.",
	webMessageKey("admin.settings.error.audit_log"):                     "Failed to record audit log",
	webMessageKey("admin.settings.error.save"):                          "Failed to save system settings",
	webMessageKey("admin.settings.flash.saved"):                         "System settings saved and applied.",
	webMessageKey("admin.settings.error.password.too_many_attempts"):    "Too many failed password attempts. Please try again later.",
	webMessageKey("admin.settings.error.password.mismatch"):             "New passwords do not match",
	webMessageKey("admin.settings.error.password.too_short"):            "Password must be at least %d characters",
	webMessageKey("admin.settings.error.password.verify_current"):       "Failed to verify current password",
	webMessageKey("admin.settings.error.password.current_incorrect"):    "Current password is incorrect",
	webMessageKey("admin.settings.error.password.reused"):               "New password must differ from current password",
	webMessageKey("admin.settings.error.password.update"):               "Failed to update password",
	webMessageKey("admin.settings.flash.password_changed"):              "Password changed successfully",
	webMessageKey("page.admin.keys.title"):                              "Packmon - Admin API Keys",
	webMessageKey("admin.keys.heading"):                                 "API Key Management",
	webMessageKey("admin.keys.created_notice"):                          "API key created. Copy it now -- it will not be shown again.",
	webMessageKey("admin.keys.new_key.aria"):                            "New API key",
	webMessageKey("admin.keys.copy_aria"):                               "Copy API key",
	webMessageKey("admin.keys.copy"):                                    "Copy",
	webMessageKey("admin.keys.create.heading"):                          "Create API key",
	webMessageKey("admin.keys.create.saving"):                           "Creating API key",
	webMessageKey("admin.keys.create.name_label"):                       "API key name",
	webMessageKey("admin.keys.create.name_placeholder"):                 "e.g. ci-pipeline, n8n-scanner",
	webMessageKey("admin.keys.create.name_help"):                        "Required. Max %d characters.",
	webMessageKey("admin.keys.create.expires_label"):                    "Expires in",
	webMessageKey("admin.keys.create.expires_help"):                     "Required. Days until the key expires, counted from now. Maximum %d days.",
	webMessageKey("admin.keys.create.expires_custom_option"):            "Custom…",
	webMessageKey("admin.keys.create.expires_custom_label"):             "Custom (days)",
	webMessageKey("admin.keys.create.expires_custom_help"):              "Enter a whole number from 1 to %d.",
	webMessageKey("admin.keys.create.current_password_label"):           "Current Password",
	webMessageKey("admin.keys.create.current_password_help"):            "Required to create a new API key.",
	webMessageKey("admin.keys.create.submit"):                           "Create API key",
	webMessageKey("admin.keys.action.revoke_aria"):                      "Revoke API key %s (ID %d)",
	webMessageKey("admin.keys.action.revoking"):                         "Revoking key",
	webMessageKey("admin.keys.action.confirm_revoke"):                   "Confirm revoke",
	webMessageKey("admin.keys.action.confirm_revoke_aria"):              "Confirm revoke API key %s (ID %d)",
	webMessageKey("admin.keys.action.revoke"):                           "Revoke",
	webMessageKey("admin.keys.action.review"):                           "Review",
	webMessageKey("admin.keys.action.revoke_question"):                  "Revoke API key %s (ID %d)?",
	webMessageKey("admin.keys.action.revoke_question_prefix"):           "Revoke API key",
	webMessageKey("admin.keys.action.revoke_question_suffix"):           "(ID %d)?",
	webMessageKey("admin.keys.action.revoke_impact"):                    "Revoking this credential immediately prevents clients using it from authenticating to Packmon APIs.",
	webMessageKey("admin.keys.action.mark_deleted_aria"):                "Mark revoked API key %s (ID %d) deleted",
	webMessageKey("admin.keys.action.mark_deleted"):                     "Mark deleted",
	webMessageKey("admin.keys.action.mark_deleted_question"):            "Mark revoked API key %s (ID %d) deleted?",
	webMessageKey("admin.keys.action.mark_deleted_question_prefix"):     "Mark revoked API key",
	webMessageKey("admin.keys.action.mark_deleted_question_suffix"):     "(ID %d) deleted?",
	webMessageKey("admin.keys.action.delete_impact"):                    "Deleting this revoked credential hides it from active administration views and keeps it unusable for API authentication.",
	webMessageKey("admin.keys.action.deleting"):                         "Deleting key",
	webMessageKey("admin.keys.action.confirm_delete_aria"):              "Confirm mark revoked API key %s (ID %d) deleted",
	webMessageKey("admin.keys.action.confirm_delete"):                   "Confirm mark deleted",
	webMessageKey("admin.keys.flash.created"):                           "API key created",
	webMessageKey("admin.keys.flash.revoked"):                           "Key revoked",
	webMessageKey("admin.keys.flash.deleted"):                           "Key deleted",
	webMessageKey("admin.keys.error.load"):                              "API keys could not be loaded. Check the server logs and database connection before changing key access.",
	webMessageKey("admin.keys.error.render_form"):                       "failed to render API key form",
	webMessageKey("admin.keys.error.generate"):                          "Failed to generate key",
	webMessageKey("admin.keys.error.create"):                            "Failed to create API key",
	webMessageKey("admin.keys.error.create_expired"):                    "Key creation request expired. Reload the page and try again.",
	webMessageKey("admin.keys.error.audit_log"):                         "Failed to record audit log",
	webMessageKey("admin.keys.error.too_many_attempts"):                 "Too many failed password attempts. Please try again later.",
	webMessageKey("admin.keys.error.verify_current_password"):           "Failed to verify current password",
	webMessageKey("admin.keys.error.current_password_incorrect"):        "Current password is incorrect",
	webMessageKey("admin.keys.error.invalid_id"):                        "Invalid key ID",
	webMessageKey("admin.keys.error.revoke"):                            "Failed to revoke key",
	webMessageKey("admin.keys.error.delete"):                            "Failed to delete key",
	webMessageKey("admin.keys.error.name_required"):                     "Key name is required",
	webMessageKey("admin.keys.error.name_too_long"):                     "Key name must be 128 characters or fewer",
	webMessageKey("admin.keys.error.expiration_required"):               "expiration is required",
	webMessageKey("admin.keys.error.expiration_invalid"):                "expiration must be a whole number of days",
	webMessageKey("admin.keys.error.expiration_future"):                 "expiration must be at least 1 day in the future",
	webMessageKey("admin.keys.error.expiration_max_lifetime"):           "expiration must be within 365 days",
	webMessageKey("page.admin.feeds.title"):                             "Packmon - Admin Feeds",
	webMessageKey("admin.feeds.heading"):                                "Feed Configuration",
	webMessageKey("admin.feeds.runtime.heading"):                        "Current Runtime",
	webMessageKey("admin.feeds.runtime.load_failed"):                    "Feed runtime status could not be loaded.",
	webMessageKey("admin.feeds.runtime.updated_count"):                  "Feed runtime updated. %d %s shown.",
	webMessageKey("admin.feeds.runtime.updated_empty"):                  "Feed runtime updated. No feeds configured.",
	webMessageKey("admin.feeds.runtime.table_aria"):                     "Admin feed runtime table",
	webMessageKey("admin.feeds.runtime.empty"):                          "No feeds configured. Check server environment variables.",
	webMessageKey("admin.feeds.runtime.info"):                           "The table below shows the current runtime state. Saved configuration changes are stored in the database and applied immediately.",
	webMessageKey("admin.feeds.runtime.warning"):                        "Runtime values are derived from the currently running process. Feed sync intervals fall back to the global default of %s when no per-feed override is configured.",
	webMessageKey("admin.feeds.runtime.refresh_label"):                  "Auto-refresh",
	webMessageKey("admin.feeds.runtime.refresh_on"):                     "On (10s)",
	webMessageKey("admin.feeds.runtime.refresh_paused"):                 "Paused",
	webMessageKey("admin.feeds.runtime.refreshing"):                     "Refreshing runtime...",
	webMessageKey("admin.feeds.runtime.refresh_now_aria"):               "Refresh runtime status now",
	webMessageKey("admin.feeds.runtime.refresh_now"):                    "Refresh now",
	webMessageKey("admin.feeds.runtime.refreshed"):                      "Runtime refreshed.",
	webMessageKey("admin.feeds.runtime.request_failed"):                 "Request failed. Showing the last loaded runtime.",
	webMessageKey("admin.feeds.runtime.request_timeout"):                "Request timed out. Showing the last loaded runtime.",
	webMessageKey("admin.feeds.runtime.update_failed"):                  "Update failed. Showing the last loaded runtime.",
	webMessageKey("admin.feeds.runtime.stale"):                          "The last loaded runtime remains visible below.",
	webMessageKey("admin.feeds.runtime.retry"):                          "Retry",
	webMessageKey("admin.feeds.status.enabled"):                         "enabled",
	webMessageKey("admin.feeds.status.disabled"):                        "disabled",
	webMessageKey("admin.feeds.status.sync"):                            "sync %s",
	webMessageKey("admin.feeds.status.key"):                             "key %s",
	webMessageKey("admin.feeds.status.key.configured"):                  "configured",
	webMessageKey("admin.feeds.status.key.missing"):                     "missing",
	webMessageKey("admin.feeds.status.key.not_configured"):              "not configured",
	webMessageKey("admin.feeds.status.key.not_required"):                "not required",
	webMessageKey("admin.feeds.status.queue_driven"):                    "queue-driven",
	webMessageKey("admin.feeds.status.runtime_unknown"):                 "unknown",
	webMessageKey("admin.feeds.status.runtime_default"):                 "%s (default)",
	webMessageKey("admin.feeds.status.runtime_override"):                "%s (override)",
	webMessageKey("admin.feeds.status.runtime_default_label"):           "default",
	webMessageKey("admin.feeds.status.runtime_default_value"):           "default (%s)",
	webMessageKey("admin.feeds.status.never"):                           "never",
	webMessageKey("admin.feeds.status.database_override"):               "database override",
	webMessageKey("admin.feeds.status.runtime_default_badge"):           "runtime default",
	webMessageKey("admin.feeds.status.differs_runtime"):                 "differs from runtime",
	webMessageKey("admin.feeds.status.matches_runtime"):                 "matches runtime",
	webMessageKey("admin.feeds.status.updated"):                         "updated",
	webMessageKey("admin.feeds.table.feed"):                             "Feed",
	webMessageKey("admin.feeds.table.status"):                           "Status",
	webMessageKey("admin.feeds.table.configuration"):                    "Configuration",
	webMessageKey("admin.feeds.table.last_sync"):                        "Last Sync",
	webMessageKey("admin.feeds.table.last_result"):                      "Last Result",
	webMessageKey("admin.feeds.table.entries"):                          "Entries",
	webMessageKey("admin.feeds.table.api_key"):                          "API Key",
	webMessageKey("admin.feeds.table.details"):                          "Details",
	webMessageKey("admin.feeds.form.heading"):                           "Saved Configuration",
	webMessageKey("admin.feeds.form.description"):                       "These values are persisted in the database and applied to the running server when saved.",
	webMessageKey("admin.feeds.form.saving"):                            "Saving feed settings",
	webMessageKey("admin.feeds.form.legend"):                            "%s feed settings",
	webMessageKey("admin.feeds.form.enabled"):                           "enabled",
	webMessageKey("admin.feeds.form.mode_label"):                        "Mode",
	webMessageKey("admin.feeds.form.mode_external_help"):                "Self-managed lets Packmon sync this feed; external expects another importer to maintain it.",
	webMessageKey("admin.feeds.form.mode_self_help"):                    "Self-managed lets Packmon sync this feed on its configured cadence.",
	webMessageKey("admin.feeds.form.sync_interval.self_label"):          "Self-sync interval",
	webMessageKey("admin.feeds.form.sync_interval.cadence_label"):       "Sync cadence",
	webMessageKey("admin.feeds.form.sync_interval.placeholder"):         "blank = global default",
	webMessageKey("admin.feeds.form.sync_interval.title"):               "Use Go duration syntax such as 30m, 2h, or 1h30m. Leave blank to use the global default.",
	webMessageKey("admin.feeds.form.sync_interval.self_help"):           "How often Packmon syncs this feed while mode is self. %s",
	webMessageKey("admin.feeds.form.sync_interval.external_help"):       "Ignored while mode is external. External feeds wait for imports or webhooks instead. %s",
	webMessageKey("admin.feeds.form.sync_interval.syntax_help"):         "Use Go duration syntax such as 30m, 2h, or 1h30m. Minimum self-sync interval is %s. Blank uses the global default.",
	webMessageKey("admin.feeds.form.sync_interval.queue_driven_help"):   "This feed does not run on a periodic timer. It is queue-driven.",
	webMessageKey("admin.feeds.form.api_key.label"):                     "API Key",
	webMessageKey("admin.feeds.form.api_key.keep_placeholder"):          "leave blank to keep stored key",
	webMessageKey("admin.feeds.form.api_key.new_placeholder"):           "paste new key",
	webMessageKey("admin.feeds.form.api_key.common_help"):               "Blank keeps the effective key. Saving an environment-provided key stores it with this database override. Vendor API usage may be billed or rate limited by the provider. It may also send package coordinates to that provider.",
	webMessageKey("admin.feeds.form.api_key.vulncheck_help"):            "Required when VulnCheck is enabled. Paste a VulnCheck API token for vulnerability and exploit enrichment. %s",
	webMessageKey("admin.feeds.form.api_key.nvd_help"):                  "Optional. Paste an NVD API key for higher rate limits; Packmon can sync NVD without it. %s",
	webMessageKey("admin.feeds.form.api_key.socket_help"):               "Required when Socket.dev is enabled. Paste a Socket.dev API token for queued package reputation lookups. %s",
	webMessageKey("admin.feeds.form.api_key.reversinglabs_help"):        "Required when ReversingLabs is enabled. Paste a ReversingLabs Spectra Assure Community API token for queued malware and removal reputation lookups. %s",
	webMessageKey("admin.feeds.form.api_key.required_help"):             "Required when %s is enabled. %s",
	webMessageKey("admin.feeds.form.api_key.optional_help"):             "Optional. %s",
	webMessageKey("admin.feeds.form.api_key.clear_label"):               "remove stored API key for %s",
	webMessageKey("admin.feeds.form.api_key.clear_required"):            "Confirm stored API key removal for this feed before saving.",
	webMessageKey("admin.feeds.form.api_key.clear_confirm"):             "I understand saving will permanently remove the stored API key for %s.",
	webMessageKey("admin.feeds.form.api_key.clear_help"):                "Selecting this removes the saved credential for %s when you save.",
	webMessageKey("admin.feeds.form.api_key.clear_sr_help"):             "Required when removing this feed's stored API key.",
	webMessageKey("admin.feeds.form.save_aria"):                         "Save %s feed settings",
	webMessageKey("admin.feeds.form.save"):                              "Save",
	webMessageKey("admin.feeds.form.edit"):                              "Edit",
	webMessageKey("admin.feeds.form.runtime_line"):                      "Runtime: %s, %s, %s, api key %s.",
	webMessageKey("admin.feeds.form.runtime_self_sync"):                 "self-sync %s",
	webMessageKey("admin.feeds.sync.button"):                            "Sync now",
	webMessageKey("admin.feeds.sync.busy"):                              "Syncing...",
	webMessageKey("admin.feeds.sync.running"):                           "Sync running",
	webMessageKey("admin.feeds.sync.aria"):                              "Sync %s now",
	webMessageKey("admin.feeds.sync.uses_runtime"):                      "Sync now uses the current runtime settings.",
	webMessageKey("admin.feeds.reset.saving"):                           "Resetting feed settings",
	webMessageKey("admin.feeds.reset.confirm"):                          "I understand reset will remove the saved configuration and stored API key for %s.",
	webMessageKey("admin.feeds.reset.help"):                             "Reset removes this database override and its stored API key credential, then falls back to environment defaults. If no environment key is configured, %s will have no stored credential.",
	webMessageKey("admin.feeds.reset.aria"):                             "Reset %s feed settings",
	webMessageKey("admin.feeds.reset.button"):                           "Reset",
	webMessageKey("admin.feeds.warning.persisted_overrides"):            "Saved feed settings override the built-in PACKMON_FEED_* defaults immediately and are reloaded on restart. Use Reset to remove the database override and fall back to environment defaults again.",
	webMessageKey("admin.feeds.warning.unknown_severity_prefix"):        "%d vulnerabilities have unknown severity.",
	webMessageKey("admin.feeds.warning.unknown_severity_body"):          "The NVD feed syncer resolves CVSS scores automatically during each sync cycle.",
	webMessageKey("admin.feeds.warning.unknown_severity_suffix"):        "Configure an NVD API key",
	webMessageKey("admin.feeds.warning.unknown_severity_tail"):          "for faster resolution (50 req/30s instead of 5 req/30s).",
	webMessageKey("admin.feeds.error.load_config"):                      "Failed to load feed configuration",
	webMessageKey("admin.feeds.error.invalid_mode"):                     "Invalid feed mode",
	webMessageKey("admin.feeds.error.invalid_sync_interval"):            "Invalid sync interval",
	webMessageKey("admin.feeds.error.ambiguous_api_key_action"):         "Choose either a new API key or clear the stored key",
	webMessageKey("admin.feeds.error.unconfirmed_api_key_clear"):        "Confirm API key removal",
	webMessageKey("admin.feeds.error.save_apply_failed"):                "Feed configuration was not saved because applying it failed",
	webMessageKey("admin.feeds.error.apply_unavailable"):                "Feed configuration was not saved because runtime apply is unavailable",
	webMessageKey("admin.feeds.error.save_conflict"):                    "Feed configuration changed while you were editing",
	webMessageKey("admin.feeds.error.audit_log"):                        "Failed to record audit log",
	webMessageKey("admin.feeds.error.save_persist"):                     "Failed to save feed configuration",
	webMessageKey("admin.feeds.error.unknown_feed"):                     "Unknown feed",
	webMessageKey("admin.feeds.error.confirm_reset"):                    "Confirm feed configuration reset",
	webMessageKey("admin.feeds.error.reset_unavailable"):                "Feed configuration was not reset because runtime reset is unavailable",
	webMessageKey("admin.feeds.error.reset_apply_failed"):               "Feed configuration was not reset because applying it failed",
	webMessageKey("admin.feeds.error.reset_persist"):                    "Failed to reset feed configuration",
	webMessageKey("admin.feeds.flash.saved_applied"):                    "Feed configuration saved and applied.",
	webMessageKey("admin.feeds.flash.saved"):                            "Feed configuration saved.",
	webMessageKey("admin.feeds.flash.reset_applied"):                    "Feed configuration reset and applied.",
	webMessageKey("admin.feeds.flash.reset"):                            "Feed configuration reset.",
	webMessageKey("admin.feeds.sync.error.unavailable_for_feed"):        "Manual sync is not available for this feed",
	webMessageKey("admin.feeds.sync.error.enabled_self_only"):           "Manual sync is available only for enabled self-managed feeds.",
	webMessageKey("admin.feeds.sync.error.unavailable_mode"):            "Manual sync is not available in this server mode",
	webMessageKey("admin.feeds.sync.error.already_running"):             "%s sync is already running.",
	webMessageKey("admin.feeds.sync.error.status"):                      "Failed to record feed sync status",
	webMessageKey("admin.feeds.sync.flash.started"):                     "%s sync started with current runtime settings.",
	webMessageKey("page.admin.advisories.title"):                        "Packmon - Admin Advisories",
	webMessageKey("admin.advisories.heading"):                           "Manual Advisories",
	webMessageKey("admin.advisories.form.edit_heading"):                 "Edit Manual Advisory",
	webMessageKey("admin.advisories.form.create_heading"):               "Create Manual Advisory",
	webMessageKey("admin.advisories.form.saving"):                       "Saving advisory",
	webMessageKey("admin.advisories.form.save"):                         "Save Manual Advisory",
	webMessageKey("admin.advisories.form.create"):                       "Create Manual Advisory",
	webMessageKey("admin.advisories.action.delete_aria"):                "Delete manual advisory %s for %s/%s",
	webMessageKey("admin.advisories.action.edit_aria"):                  "Edit manual advisory %s for %s/%s",
	webMessageKey("admin.advisories.action.edit"):                       "Edit",
	webMessageKey("admin.advisories.action.delete"):                     "Delete",
	webMessageKey("admin.advisories.action.review"):                     "Review",
	webMessageKey("admin.advisories.action.deleting"):                   "Deleting advisory",
	webMessageKey("admin.advisories.action.delete_impact"):              "Deleting this advisory removes manually maintained scan coverage for this package.",
	webMessageKey("admin.advisories.action.confirm_label"):              "Type this advisory ID to confirm",
	webMessageKey("admin.advisories.action.confirm_input_aria"):         "Type %s to confirm deletion",
	webMessageKey("admin.advisories.action.confirm_delete_aria"):        "Confirm delete manual advisory %s for %s/%s",
	webMessageKey("admin.advisories.action.confirm_delete"):             "Confirm delete",
	webMessageKey("admin.advisories.error.load"):                        "Manual advisories could not be loaded. Check the server logs and database connection before changing advisory coverage.",
	webMessageKey("admin.advisories.error.not_found"):                   "Manual advisory not found",
	webMessageKey("admin.advisories.error.prepare_form"):                "Failed to prepare manual advisory form. Reload the page and try again.",
	webMessageKey("admin.advisories.error.load_existing"):               "Failed to load existing advisory",
	webMessageKey("admin.advisories.error.invalid_revision"):            "Invalid advisory revision",
	webMessageKey("admin.advisories.field.finding_type"):                "Select vulnerability or malicious.",
	webMessageKey("admin.advisories.field.ecosystem_required"):          "Select a supported package ecosystem.",
	webMessageKey("admin.advisories.field.name_required"):               "Enter a package name.",
	webMessageKey("admin.advisories.field.severity_required"):           "Select CRITICAL, HIGH, MEDIUM, or LOW.",
	webMessageKey("admin.advisories.field.summary_required"):            "Enter a summary.",
	webMessageKey("admin.advisories.error.invalid_finding_type"):        "Invalid finding type",
	webMessageKey("admin.advisories.error.required_fields"):             "All required fields must be filled",
	webMessageKey("admin.advisories.error.invalid_severity"):            "Invalid severity",
	webMessageKey("admin.advisories.error.unknown_ecosystem"):           "Unknown ecosystem",
	webMessageKey("admin.advisories.error.docker_unsupported"):          "Docker is inventory-only and cannot be used for manual scan advisories",
	webMessageKey("admin.advisories.field.max_length"):                  "Use %d characters or fewer.",
	webMessageKey("admin.advisories.error.max_length"):                  "Field exceeds maximum length",
	webMessageKey("admin.advisories.error.generate_id"):                 "Failed to generate advisory ID",
	webMessageKey("admin.advisories.error.id_prefix"):                   "Advisory ID must start with manual:",
	webMessageKey("admin.advisories.error.save_default"):                "Manual advisory could not be saved",
	webMessageKey("admin.advisories.error.audit_log"):                   "Failed to record audit log",
	webMessageKey("admin.advisories.error.conflict"):                    "Advisory changed while you were editing. Reload and apply your changes again.",
	webMessageKey("admin.advisories.error.update"):                      "Failed to update advisory",
	webMessageKey("admin.advisories.error.create"):                      "Failed to create advisory",
	webMessageKey("admin.advisories.flash.created"):                     "Advisory created",
	webMessageKey("admin.advisories.flash.updated"):                     "Advisory updated",
	webMessageKey("admin.advisories.error.missing_id"):                  "Missing advisory ID",
	webMessageKey("admin.advisories.error.confirm_delete_id"):           "Confirm advisory ID before deleting",
	webMessageKey("admin.advisories.error.load_delete"):                 "Failed to load advisory",
	webMessageKey("admin.advisories.error.delete_not_found"):            "Advisory not found",
	webMessageKey("admin.advisories.error.delete"):                      "Failed to delete advisory",
	webMessageKey("admin.advisories.flash.deleted"):                     "Advisory deleted",
	webMessageKey("page.admin.queue.title"):                             "Packmon - Admin Queue",
	webMessageKey("admin.queue.heading"):                                "Queue Management",
	webMessageKey("admin.queue.row.actions_aria"):                       "Show actions for queue job %d %s/%s",
	webMessageKey("admin.queue.row.actions"):                            "Actions",
	webMessageKey("admin.queue.row.manage"):                             "Manage",
	webMessageKey("admin.queue.row.priority.saving"):                    "Saving priority",
	webMessageKey("admin.queue.row.priority.aria"):                      "Priority for queue job %d %s/%s",
	webMessageKey("admin.queue.row.priority.save_aria"):                 "Save priority for queue job %d %s/%s",
	webMessageKey("admin.queue.row.priority.save"):                      "Save Priority",
	webMessageKey("admin.queue.row.pause.saving"):                       "Pausing job",
	webMessageKey("admin.queue.row.pause_aria"):                         "Pause queue job %d %s/%s",
	webMessageKey("admin.queue.row.pause"):                              "Pause",
	webMessageKey("admin.queue.row.resume.saving"):                      "Resuming job",
	webMessageKey("admin.queue.row.resume_aria"):                        "Resume queue job %d %s/%s",
	webMessageKey("admin.queue.row.resume"):                             "Resume",
	webMessageKey("admin.queue.row.retry.saving"):                       "Retrying job",
	webMessageKey("admin.queue.row.retry_aria"):                         "Retry queue job %d %s/%s",
	webMessageKey("admin.queue.row.retry"):                              "Retry",
	webMessageKey("admin.queue.bulk.purge_aria"):                        "Purge completed and errored queue jobs",
	webMessageKey("admin.queue.bulk.purge"):                             "Purge Completed/Errored",
	webMessageKey("admin.queue.bulk.review"):                            "Review",
	webMessageKey("admin.queue.bulk.purge_question"):                    "Purge %s?",
	webMessageKey("admin.queue.bulk.purge_impact"):                      "This removes completed and errored queue records from the admin queue history.",
	webMessageKey("admin.queue.bulk.purging"):                           "Purging queue jobs",
	webMessageKey("admin.queue.bulk.confirm_purge_aria"):                "Confirm purge %d completed and errored queue jobs",
	webMessageKey("admin.queue.bulk.confirm_purge"):                     "Confirm purge",
	webMessageKey("admin.queue.bulk.no_purge"):                          "No completed or errored jobs to purge.",
	webMessageKey("admin.queue.bulk.clear_aria"):                        "Clear %s queue jobs",
	webMessageKey("admin.queue.bulk.clear"):                             "Clear %s",
	webMessageKey("admin.queue.bulk.clear_question"):                    "Clear %s?",
	webMessageKey("admin.queue.bulk.clear_impact"):                      "This removes %s refresh work from the queue; it will not be processed unless it is recreated.",
	webMessageKey("admin.queue.bulk.clearing"):                          "Clearing queue jobs",
	webMessageKey("admin.queue.bulk.confirm_clear_aria"):                "Confirm clear %d %s queue %s",
	webMessageKey("admin.queue.bulk.confirm_clear"):                     "Confirm clear %s",
	webMessageKey("admin.queue.bulk.no_clear"):                          "No %s queue jobs to clear.",
	webMessageKey("admin.queue.error.stats_load"):                       "Queue stats could not be loaded. Check the server logs and database connection before relying on these counters.",
	webMessageKey("admin.queue.error.jobs_load"):                        "Queue jobs could not be loaded. Check the server logs and database connection before changing queue state.",
	webMessageKey("admin.queue.error.audit_log"):                        "Failed to record audit log",
	webMessageKey("admin.queue.error.purge"):                            "Purge failed",
	webMessageKey("admin.queue.flash.purged"):                           "Purged %d %s.",
	webMessageKey("admin.queue.error.invalid_priority"):                 "Invalid priority",
	webMessageKey("admin.queue.error.priority_update"):                  "Priority update failed",
	webMessageKey("admin.queue.flash.priority_updated"):                 "Priority updated",
	webMessageKey("admin.queue.flash.job_paused"):                       "Job paused",
	webMessageKey("admin.queue.error.job_pause"):                        "Job paused failed",
	webMessageKey("admin.queue.flash.job_resumed"):                      "Job resumed",
	webMessageKey("admin.queue.error.job_resume"):                       "Job resumed failed",
	webMessageKey("admin.queue.flash.job_retry"):                        "Job queued for retry",
	webMessageKey("admin.queue.error.job_retry"):                        "Job queued for retry failed",
	webMessageKey("admin.queue.error.invalid_status"):                   "Invalid queue status",
	webMessageKey("admin.queue.error.clear"):                            "Queue clear failed",
	webMessageKey("admin.queue.flash.cleared"):                          "Cleared %d %s.",
	webMessageKey("admin.queue.error.invalid_job_id"):                   "Invalid queue job ID",
	webMessageKey("admin.queue.error.status_filter_unknown"):            "Unknown queue status filter; showing all jobs.",
	webMessageKey("admin.queue.filter.all"):                             "All",
	webMessageKey("admin.queue.filter.with_count"):                      "%s (%d)",
	webMessageKey("admin.queue.stat.show_aria"):                         "Show %s queue jobs (%d)",
	webMessageKey("admin.queue.count.pending.singular"):                 "pending queue job",
	webMessageKey("admin.queue.count.pending.plural"):                   "pending queue jobs",
	webMessageKey("admin.queue.count.paused.singular"):                  "paused queue job",
	webMessageKey("admin.queue.count.paused.plural"):                    "paused queue jobs",
	webMessageKey("admin.queue.count.purge.singular"):                   "completed/errored job",
	webMessageKey("admin.queue.count.purge.plural"):                     "completed/errored jobs",
	webMessageKey("admin.queue.count.queue_job.singular"):               "queue job",
	webMessageKey("admin.queue.count.completed_errored.plural"):         "completed/errored jobs",
	webMessageKey("admin.queue.count.queue_jobs.plural"):                "queue jobs",
	webMessageKey("admin.queue.empty.page.title"):                       "No queue jobs on this page.",
	webMessageKey("admin.queue.empty.page.message"):                     "The current page is past the available queue results.",
	webMessageKey("admin.queue.empty.page.primary"):                     "Back to first page",
	webMessageKey("admin.queue.empty.view_all"):                         "View all queue jobs",
	webMessageKey("admin.queue.empty.filtered.title"):                   "No %s queue jobs match this filter.",
	webMessageKey("admin.queue.empty.filtered.message"):                 "Try another status filter or return to the full queue.",
	webMessageKey("admin.queue.empty.all.title"):                        "Queue is empty.",
	webMessageKey("admin.queue.empty.all.message"):                      "Queue jobs appear here after feed refreshes are scheduled.",
	webMessageKey("admin.queue.empty.all.primary"):                      "Open feed controls",
	webMessageKey("search.error.query_too_long"):                        "Search query must be %d characters or fewer.",
	webMessageKey("search.error.query_too_short"):                       "Enter at least %d characters to search.",
	webMessageKey("search.error.failed"):                                "Search failed. Try again or narrow the filters.",
	webMessageKey("search.error.invalid_filter"):                        "Invalid %s filter %q. Use %s.",
}

func webMessage(key webMessageKey, args ...any) string {
	format, ok := webMessagesEN[key]
	if !ok {
		return string(key)
	}
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

func templateMessage(key string, args ...any) string {
	return webMessage(webMessageKey(strings.TrimSpace(key)), args...)
}

// Message returns a user-facing message from the shared web catalog.
func Message(key string, args ...any) string {
	return webMessage(webMessageKey(strings.TrimSpace(key)), args...)
}

func newTabAriaLabel(label string) string {
	return webMessage(webMessageNewTabAriaLabel, strings.TrimSpace(label))
}

func newTabSRText() string {
	return webMessage(webMessageNewTabScreenReader)
}

func formatTimeAgoAt(t, now time.Time) string {
	if t.IsZero() {
		return webMessage(webMessageNever)
	}
	d := now.Sub(t)
	if d < 0 {
		return formatTimeUntil(-d)
	}
	switch {
	case d < time.Minute:
		return webMessage(webMessageJustNow)
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return webMessage(webMessageMinuteAgoOne)
		}
		return webMessage(webMessageMinuteAgoOther, m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return webMessage(webMessageHourAgoOne)
		}
		return webMessage(webMessageHourAgoOther, h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return webMessage(webMessageDayAgoOne)
		}
		return webMessage(webMessageDayAgoOther, days)
	}
}

func formatTimeUntil(d time.Duration) string {
	switch {
	case d < time.Minute:
		return webMessage(webMessageLessThanMinute)
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return webMessage(webMessageMinuteFutureOne)
		}
		return webMessage(webMessageMinuteFutureOther, m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return webMessage(webMessageHourFutureOne)
		}
		return webMessage(webMessageHourFutureOther, h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return webMessage(webMessageDayFutureOne)
		}
		return webMessage(webMessageDayFutureOther, days)
	}
}

// formatFixedIn renders a fixed-version value for the package details UI.
// Bare versions are shown as a lower-bound safe range (">= 1.2.3"), while
// values that already carry an operator are preserved as-is.
func formatFixedIn(fixed string) string {
	fixed = strings.TrimSpace(fixed)
	if fixed == "" {
		return ""
	}
	switch fixed[0] {
	case '<', '>', '=':
		return fixed
	default:
		return ">= " + fixed
	}
}

// severityClass returns Tailwind CSS classes for a given severity string.
func severityClass(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "pm-badge-severity-critical"
	case "HIGH":
		return "pm-badge-severity-high"
	case "MEDIUM":
		return "pm-badge-severity-medium"
	case "LOW":
		return "pm-badge-severity-low"
	default:
		return "pm-badge-severity-default"
	}
}

// statusClass returns Tailwind CSS classes for a feed health status.
func statusClass(status string) string {
	switch strings.ToLower(status) {
	case "healthy":
		return "pm-badge-status-healthy"
	case "warning":
		return "pm-badge-status-warning"
	case "error":
		return "pm-badge-status-error"
	case "configured":
		return "pm-badge-status-configured"
	case "running":
		return "pm-badge-status-running"
	case "pending":
		return "pm-badge-status-pending"
	case "disabled":
		return "pm-badge-status-disabled"
	default:
		return "pm-badge-status-default"
	}
}

// truncate shortens a string to max characters, appending "..." if truncated.
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max < 4 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func findingTypeLabels(csv string) []string {
	parts := strings.Split(csv, ",")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch part {
		case "vulnerability":
			labels = append(labels, "Vulnerability")
		case "malicious":
			labels = append(labels, "Malicious package")
		case "supply_chain_risk":
			labels = append(labels, "Supply-chain risk")
		case "lifecycle":
			labels = append(labels, "Lifecycle")
		default:
			labels = append(labels, part)
		}
	}
	return labels
}

// seq returns a slice of ints from 0 to n-1 for range iteration in templates.
func seq(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}
