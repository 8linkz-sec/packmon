package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/8linkz-sec/packmon/internal/server/middleware"
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
			defer closeSilently(store)

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
			renderer := web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{HideAdmin: true})

			mux := http.NewServeMux()
			web.RegisterRoutes(mux, store, renderer, logger)
			registerLocalDashboardRoutes(mux)

			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", flagPort))
			if err != nil {
				return fmt.Errorf("listen on localhost:%d: %w", flagPort, err)
			}
			defer closeSilently(listener)

			srv := newLocalDashboardServer(middleware.SecurityHeaders(false, "", nil)(mux))

			serveErr := make(chan error, 1)
			go func() {
				serveErr <- srv.Serve(listener)
			}()

			url := "http://" + listener.Addr().String()
			fmt.Printf("Local dashboard available at %s\n", url)
			fmt.Println("Press Ctrl+C to stop.")

			if options.onReady != nil {
				options.onReady(url)
			}

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
					closeSilently(srv)
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
	http.Error(w, "Local dashboard is read-only. Admin functions require packmon-server.", http.StatusNotFound)
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

func startBrowserCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
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
