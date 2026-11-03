package postgres

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF212StoreConfigurationErrorsDoNotExposePasswords(t *testing.T) {
	t.Parallel()

	t.Run("new pool config URL", func(t *testing.T) {
		t.Parallel()

		const password = "f212-url-password"
		config, err := newPgxPoolConfig(
			"postgres://packmon:"+password+"@localhost/packmon?pool_max_conns=not-a-number",
			nil,
		)
		if config != nil {
			t.Fatal("newPgxPoolConfig(invalid DSN) config is non-nil")
		}
		f212AssertSanitizedConfigError(t, err, password)
	})

	t.Run("New keyword DSN", func(t *testing.T) {
		t.Parallel()

		const password = "f212 keyword password"
		store, err := New(
			context.Background(),
			"host=localhost user=packmon password='"+password+"' dbname=packmon pool_max_conns=not-a-number",
			nil,
			nil,
		)
		if store != nil {
			t.Fatal("New(invalid DSN) store is non-nil")
		}
		f212AssertSanitizedConfigError(t, err, password)
	})
}

func TestF212NewPgxPoolConfigAcceptsNilPoolConfig(t *testing.T) {
	t.Parallel()

	config, err := newPgxPoolConfig("postgres://packmon@localhost:5432/packmon?sslmode=disable&connect_timeout=4", nil)
	if err != nil {
		t.Fatalf("newPgxPoolConfig(nil) error = %v", err)
	}
	if config == nil {
		t.Fatal("newPgxPoolConfig(nil) config = nil")
	}
	if config.ConnConfig.ConnectTimeout != 4*time.Second {
		t.Fatalf("ConnectTimeout = %s, want DSN timeout 4s", config.ConnConfig.ConnectTimeout)
	}
}

func TestF212NewPingFailureClosesStoreAndDoesNotExposePassword(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for inert PostgreSQL endpoint: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	const password = "f212-ping-password"
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	store, err := New(ctx, fmt.Sprintf("postgres://packmon:%s@%s/packmon?sslmode=disable", password, listener.Addr()), nil, nil)
	if store != nil {
		t.Fatal("New(inert endpoint) store is non-nil")
	}
	if err != nil && strings.Contains(err.Error(), password) {
		t.Fatal("New(inert endpoint) error exposed the configured password")
	}
	if err == nil || !strings.Contains(err.Error(), "postgres: ping:") {
		t.Fatalf("New(inert endpoint) error = %s, want ping context", f212RedactTestPassword(err, password))
	}
}

func TestF212JoinSortedCSVBoundaryMatrix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "blank segments", in: " ,\t,  ,", want: ""},
		{name: "trim deduplicate and sort", in: " zeta, alpha, zeta ,, beta ", want: "alpha, beta, zeta"},
		{name: "case sensitive ordering", in: "osv, OSV, osv", want: "OSV, osv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := joinSortedCSV(tc.in); got != tc.want {
				t.Fatalf("joinSortedCSV(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestF212SortSearchResultsUsesVersionAsFinalTieBreaker(t *testing.T) {
	t.Parallel()

	var nilResults []db.PackageSearchResult
	sortSearchResults(nilResults)
	if nilResults != nil {
		t.Fatalf("sortSearchResults(nil) = %#v, want nil", nilResults)
	}

	results := []db.PackageSearchResult{
		{Ecosystem: "npm", Name: "same", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "same", Version: "1.10.0"},
		{Ecosystem: "npm", Name: "same", Version: ""},
		{Ecosystem: "pypi", Name: "same", Version: "0.1.0"},
		{Ecosystem: "npm", Name: "alpha", Version: "9.0.0"},
	}
	want := []db.PackageSearchResult{
		{Ecosystem: "npm", Name: "alpha", Version: "9.0.0"},
		{Ecosystem: "npm", Name: "same", Version: ""},
		{Ecosystem: "npm", Name: "same", Version: "1.10.0"},
		{Ecosystem: "npm", Name: "same", Version: "2.0.0"},
		{Ecosystem: "pypi", Name: "same", Version: "0.1.0"},
	}

	sortSearchResults(results)
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("sortSearchResults() = %#v, want %#v", results, want)
	}
}

func f212AssertSanitizedConfigError(t *testing.T, err error, password string) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), password) {
		t.Fatal("invalid DSN error exposed the configured password")
	}
	if err == nil || !strings.Contains(err.Error(), "postgres: parse dsn:") {
		t.Fatalf("invalid DSN error = %s, want parse context", f212RedactTestPassword(err, password))
	}
}

func f212RedactTestPassword(err error, password string) string {
	if err == nil {
		return "<nil>"
	}
	return strings.ReplaceAll(err.Error(), password, "[redacted]")
}
