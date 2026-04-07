// Package web provides the HTML-based web interface for the Packmon server.
// All templates are loaded from an embedded filesystem and rendered using
// Go's html/template package. HTMX handles client-side interactivity;
// Tailwind CSS is built into a local static asset.
package web

import (
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// Renderer loads, caches, and executes HTML templates from an embedded FS.
type Renderer struct {
	fs    fs.FS
	mu    sync.RWMutex
	cache map[string]*template.Template
	funcs template.FuncMap
	dev   bool // when true, templates are reloaded on every render
}

// NewRenderer creates a Renderer backed by the given filesystem.
// If dev is true, templates are re-parsed on every call (useful during
// development but slower).
func NewRenderer(fsys fs.FS, dev bool) *Renderer {
	return &Renderer{
		fs:    fsys,
		cache: make(map[string]*template.Template),
		funcs: defaultFuncMap(),
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
	return t.ExecuteTemplate(w, "layout", data)
}

// RenderPartial executes the named template without the layout wrapper.
// This is used for HTMX partial responses (hx-swap fragments).
func (r *Renderer) RenderPartial(w io.Writer, name, block string, data any) error {
	t, err := r.load(name)
	if err != nil {
		return fmt.Errorf("render partial %s/%s: %w", name, block, err)
	}
	return t.ExecuteTemplate(w, block, data)
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
	t := template.New("").Funcs(r.funcs)

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
	if _, err := t.Parse(string(pageBytes)); err != nil {
		return nil, fmt.Errorf("parse page %s: %w", name, err)
	}

	return t, nil
}

// defaultFuncMap returns the template functions available to every template.
func defaultFuncMap() template.FuncMap {
	return template.FuncMap{
		"formatTime":    formatTime,
		"formatTimeAgo": formatTimeAgo,
		"formatFixedIn": formatFixedIn,
		"severityClass": severityClass,
		"statusClass":   statusClass,
		"truncate":      truncate,
		"lower":         strings.ToLower,
		"upper":         strings.ToUpper,
		"hasPrefix":     strings.HasPrefix,
		"add":           func(a, b int) int { return a + b },
		"sub":           func(a, b int) int { return a - b },
		"seq":           seq,
	}
}

// formatTime renders a time.Time as a human-readable string.
// Returns "-" for zero times.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// formatTimeAgo renders a time.Time as a relative "X ago" string.
func formatTimeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
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
		return "bg-red-100 text-red-800 border-red-200"
	case "HIGH":
		return "bg-orange-100 text-orange-800 border-orange-200"
	case "MEDIUM":
		return "bg-yellow-100 text-yellow-800 border-yellow-200"
	case "LOW":
		return "bg-blue-100 text-blue-800 border-blue-200"
	default:
		return "bg-gray-100 text-gray-800 border-gray-200"
	}
}

// statusClass returns Tailwind CSS classes for a feed health status.
func statusClass(status string) string {
	switch strings.ToLower(status) {
	case "healthy":
		return "bg-green-100 text-green-800"
	case "warning":
		return "bg-yellow-100 text-yellow-800"
	case "error":
		return "bg-red-100 text-red-800"
	case "configured":
		return "bg-blue-100 text-blue-800"
	case "pending":
		return "bg-gray-100 text-gray-700"
	case "disabled":
		return "bg-gray-200 text-gray-600"
	default:
		return "bg-gray-100 text-gray-800"
	}
}

// truncate shortens a string to max characters, appending "..." if truncated.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// seq returns a slice of ints from 0 to n-1 for range iteration in templates.
func seq(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}
