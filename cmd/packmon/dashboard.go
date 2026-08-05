package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/httpsecurity"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/web"
	"github.com/spf13/cobra"
)

type dashboardOptions struct {
	shutdownTimeout time.Duration
	onReady         func(string)
	openBrowser     func(string) error
}

func newDashboardCmd() *cobra.Command {
	return newDashboardCmdWithOptions(dashboardOptions{})
}

func newDashboardCmdWithOptions(options dashboardOptions) *cobra.Command {
	if options.shutdownTimeout <= 0 {
		options.shutdownTimeout = 5 * time.Second
	}
	if options.openBrowser == nil {
		options.openBrowser = openBrowser
	}

	var (
		flagPort int
		flagOpen bool
	)

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the local Packmon dashboard",
		Long:  "Starts a local read-only dashboard on localhost using the local SQLite database and scan history.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signalContext(cmd.Context())
			defer stop()

			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}

			store, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer ioutils.CloseSilently(store)

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
			renderer := web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{HideAdmin: true})

			mux := http.NewServeMux()
			web.RegisterRoutesWithOptions(mux, web.NewDBStoreAdapter(store), renderer, logger, web.RouteOptions{
				Dashboard: web.DashboardOptions{
					LocalDBWarning: func(ctx context.Context) string {
						return localDashboardDBWarning(ctx, store, logger)
					},
				},
			})
			registerLocalDashboardRoutes(mux)

			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", flagPort))
			if err != nil {
				return fmt.Errorf("listen on localhost:%d: %w", flagPort, err)
			}
			defer ioutils.CloseSilently(listener)

			srv := newLocalDashboardServer(httpsecurity.SecurityHeaders(false, "", nil)(mux))

			serveErr := make(chan error, 1)
			go func() {
				serveErr <- srv.Serve(listener)
			}()

			url := "http://" + listener.Addr().String()
			announceLocalDashboardReady(cmd.OutOrStdout(), url, options.onReady)

			if flagOpen {
				go func() {
					time.Sleep(200 * time.Millisecond)
					if err := options.openBrowser(url); err != nil {
						fmt.Fprintf(os.Stderr, "warning: unable to open dashboard browser: %v\n", err)
					}
				}()
			}

			select {
			case err := <-serveErr:
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					return fmt.Errorf("serve dashboard: %w", err)
				}
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), options.shutdownTimeout)
				err := srv.Shutdown(shutdownCtx)
				cancel()
				if err != nil {
					ioutils.CloseSilently(srv)
				}

				err = <-serveErr
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					return fmt.Errorf("serve dashboard: %w", err)
				}
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.IntVar(&flagPort, "port", 0, "localhost port to bind to (default: random free port)")
	f.BoolVar(&flagOpen, "open", false, "open the dashboard in the default browser")

	return cmd
}

func announceLocalDashboardReady(stdout io.Writer, url string, onReady func(string)) {
	if onReady != nil {
		onReady(url)
	}

	_, _ = fmt.Fprintf(stdout, "Local dashboard available at %s\n", url)
	_, _ = fmt.Fprintln(stdout, "Press Ctrl+C to stop.")
}

func localDashboardDBWarning(ctx context.Context, store *sqlite.Store, logger *slog.Logger) string {
	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		if logger != nil {
			logger.Warn("dashboard: failed to verify local database freshness", "error", err)
		}
		return "Local database freshness could not be verified. Results may be incomplete. Update with: packmon db sync."
	}
	if info == nil || !info.DBStale {
		return ""
	}
	if info.DBAgeDays != nil {
		return fmt.Sprintf("Local database last synced %s ago. Results may be incomplete. Update with: packmon db sync.", plural.Count(*info.DBAgeDays, "day", "days"))
	}
	return "Local database is stale. Results may be incomplete. Update with: packmon db sync."
}

func newLocalDashboardServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func registerLocalDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", localAdminUnavailable)
	mux.HandleFunc("GET /admin/", localAdminUnavailable)
	mux.HandleFunc("GET /admin/login", localAdminUnavailable)
	mux.HandleFunc("GET /.well-known/change-password", localAdminUnavailable)
}

func localAdminUnavailable(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Packmon - Admin unavailable</title>
  <style>
    body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; color: #111827; background: #f9fafb; }
    main { max-width: 42rem; margin: 12vh auto; padding: 2rem; }
    h1 { margin: 0 0 0.75rem; font-size: 1.75rem; line-height: 1.2; }
    p { margin: 0 0 1.25rem; color: #4b5563; line-height: 1.6; }
    nav { display: flex; flex-wrap: wrap; gap: 0.75rem; }
    a { display: inline-flex; min-height: 2.75rem; align-items: center; border-radius: 0.375rem; padding: 0 1rem; font-weight: 600; color: #1d4ed8; background: #fff; border: 1px solid #9ca3af; text-decoration: none; }
    a:first-child { color: #fff; background: #2563eb; border-color: #2563eb; }
  </style>
</head>
<body>
  <main>
    <h1>Admin unavailable in the local dashboard</h1>
    <p>Local dashboard is read-only. Admin functions require packmon-server.</p>
    <nav aria-label="Local dashboard destinations">
      <a href="/">Dashboard</a>
      <a href="/search">Search</a>
      <a href="/feeds">Feed status</a>
    </nav>
  </main>
</body>
</html>`)
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func openBrowser(url string) error {
	if err := validateBrowserURL(url); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "windows":
		// #nosec G204 -- URL is validated and only opened in the user's default browser.
		return startBrowserCommand(exec.Command("rundll32", "url.dll,FileProtocolHandler", url))
	case "darwin":
		// #nosec G204 -- URL is validated and only opened in the user's default browser.
		return startBrowserCommand(exec.Command("open", url))
	default:
		// #nosec G204 -- URL is validated and only opened in the user's default browser.
		return startBrowserCommand(exec.Command("xdg-open", url))
	}
}

var (
	browserProcessStartupWait = 500 * time.Millisecond
	waitBrowserCommand        = func(cmd *exec.Cmd) error {
		return cmd.Wait()
	}
)

func startBrowserCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- waitBrowserCommand(cmd)
	}()

	if browserProcessStartupWait <= 0 {
		return nil
	}
	timer := time.NewTimer(browserProcessStartupWait)
	defer timer.Stop()

	select {
	case err := <-waitErr:
		return err
	case <-timer.C:
	}
	return nil
}

func validateBrowserURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse browser URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported browser URL scheme %q", parsed.Scheme)
	}

	switch parsed.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return nil
	default:
		return fmt.Errorf("refusing to open non-local URL %q", rawURL)
	}
}
