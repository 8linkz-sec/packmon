package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	pgstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type privacyExportStore interface {
	ExportPrivacyMetadata(context.Context, db.PrivacyExportSelector, *db.AdminAuditEntry) (*db.PrivacyExport, error)
	Close() error
}

var (
	privacyExportOutput    io.Writer = os.Stdout
	openPrivacyExportStore           = func(ctx context.Context, dsn string, timeout time.Duration) (privacyExportStore, error) {
		return pgstore.New(ctx, dsn, nil, &pgstore.PoolConfig{MaxConns: 2, MinConns: 1, ConnectTimeout: timeout})
	}
)

func runPrivacy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: packmon-server privacy export --selector type=value [--format json]")
	}
	switch args[0] {
	case "export":
		return runPrivacyExport(args[1:])
	default:
		return fmt.Errorf("unknown privacy command %q", args[0])
	}
}

func runPrivacyExport(args []string) error {
	flags := flag.NewFlagSet("privacy export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectorRaw := flags.String("selector", "", "exact selector in type=value form")
	format := flags.String("format", "json", "output format")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected privacy export argument %q", flags.Arg(0))
	}
	if *format != "json" {
		return fmt.Errorf("unsupported privacy export format %q", *format)
	}
	selector, err := parsePrivacySelector(*selectorRaw)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := requireProductionAdminAuditHMACKey(cfg); err != nil {
		return err
	}
	if err := configureAdminAuditDigestHMACKey(cfg); err != nil {
		return err
	}
	timeout := databaseStartupTimeout(cfg)
	dsn, err := dsnWithConnectTimeout(cfg.DB.DSN(), timeout)
	if err != nil {
		return fmt.Errorf("prepare privacy export DSN: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	version, dirty, err := readDatabaseMigrationVersionContext(ctx, dsn)
	if err != nil {
		return fmt.Errorf("read schema version for privacy export: %w", err)
	}
	if dirty {
		return fmt.Errorf("privacy export refused: schema is dirty at version %d", version)
	}
	if version != pgstoreExpectedSchemaVersion() {
		return fmt.Errorf("privacy export refused: schema version %d, want %d", version, pgstoreExpectedSchemaVersion())
	}

	store, err := openPrivacyExportStore(ctx, dsn, timeout)
	if err != nil {
		return err
	}
	defer ioutils.CloseSilently(store)

	export, err := store.ExportPrivacyMetadata(ctx, selector, privacyExportAuditEntry(selector))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(privacyExportOutput)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(export); err != nil {
		return fmt.Errorf("write privacy export JSON: %w", err)
	}
	return nil
}

func parsePrivacySelector(raw string) (db.PrivacyExportSelector, error) {
	kind, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
	if !ok {
		return db.PrivacyExportSelector{}, errors.New("privacy export selector must use type=value")
	}
	selector := db.PrivacyExportSelector{
		Type:  strings.TrimSpace(kind),
		Value: strings.TrimSpace(value),
	}
	if selector.Type == "" || selector.Value == "" {
		return db.PrivacyExportSelector{}, errors.New("privacy export selector type and value are required")
	}
	switch selector.Type {
	case db.PrivacySelectorClientIP:
		if _, err := netip.ParseAddr(selector.Value); err != nil {
			return db.PrivacyExportSelector{}, fmt.Errorf("invalid client-ip selector: %w", err)
		}
	case db.PrivacySelectorAPIKeyID:
		id, err := strconv.Atoi(selector.Value)
		if err != nil || id <= 0 {
			return db.PrivacyExportSelector{}, fmt.Errorf("invalid api-key-id selector %q", selector.Value)
		}
	case db.PrivacySelectorRepoName, db.PrivacySelectorAPIKeyName, db.PrivacySelectorCorrelationID:
	default:
		return db.PrivacyExportSelector{}, fmt.Errorf("unsupported privacy export selector type %q", selector.Type)
	}
	return selector, nil
}

func privacyExportAuditEntry(selector db.PrivacyExportSelector) *db.AdminAuditEntry {
	raw, _ := json.Marshal(map[string]string{
		"selector_type":   selector.Type,
		"selector_digest": selector.Digest(),
	})
	return &db.AdminAuditEntry{
		Action:  "privacy_export",
		Details: raw,
	}
}

func pgstoreExpectedSchemaVersion() uint {
	return uint(migrations.ExpectedVersion)
}
