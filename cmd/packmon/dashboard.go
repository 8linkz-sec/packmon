package main

import (
	"context"
	"errors"
	"fmt"
	"html"
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

	"github.com/8linkz/packmon/internal/db/sqlite"
	"github.com/8linkz/packmon/internal/web"
	"github.com/spf13/cobra"
)

func newDashboardCmd() *cobra.Command {
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

			store, err := sqlite.New(defaultDBPath())
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer closeSilently(store)

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
			renderer := web.NewRenderer(web.TemplateFS(), false)

			mux := http.NewServeMux()
			web.RegisterRoutes(mux, store, renderer, logger)
			registerLocalDashboardRoutes(mux)

			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", flagPort))
			if err != nil {
				return fmt.Errorf("listen on localhost:%d: %w", flagPort, err)
			}
			defer closeSilently(listener)

			url := "http://" + listener.Addr().String()
			fmt.Printf("Local dashboard available at %s\n", url)
			fmt.Println("Press Ctrl+C to stop.")

			if flagOpen {
				go func() {
					time.Sleep(200 * time.Millisecond)
					_ = openBrowser(url)
				}()
			}

			srv := &http.Server{
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
			}

			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
			}()

			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve dashboard: %w", err)
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.IntVar(&flagPort, "port", 0, "localhost port to bind to (default: random free port)")
	f.BoolVar(&flagOpen, "open", true, "open the dashboard in the default browser")

	return cmd
}

func registerLocalDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", redirectHome)
	mux.HandleFunc("GET /admin/", redirectHome)
	mux.HandleFunc("GET /admin/login", redirectHome)
	mux.HandleFunc("GET /.well-known/change-password", redirectHome)
	mux.HandleFunc("POST /api/v1/packages/{ecosystem}/{rest...}", localRefreshNotice)
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func localRefreshNotice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)

	ecosystem := html.EscapeString(r.PathValue("ecosystem"))
	name := html.EscapeString(r.PathValue("rest"))

	_, _ = fmt.Fprintf(w, `<div id="refresh-status" class="rounded-md border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-800">Local dashboard is read-only. Refresh requests for <strong>%s/%s</strong> need a running packmon server.</div>`, ecosystem, name)
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
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		// #nosec G204 -- URL is validated and only opened in the user's default browser.
		return exec.Command("open", url).Start()
	default:
		// #nosec G204 -- URL is validated and only opened in the user's default browser.
		return exec.Command("xdg-open", url).Start()
	}
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
