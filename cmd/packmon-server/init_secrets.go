package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/envfile"
)

// runInitSecrets generates any missing/empty required secrets into a .env file,
// seeding a fresh file from .env.example. Existing non-empty values are never
// overwritten. It never prints secret values.
func runInitSecrets(args []string) error {
	return initSecrets(args, os.Stdout, os.Stderr)
}

// initSecrets is runInitSecrets with injectable output streams. The status
// line goes to stdout and warnings to stderr; neither ever contains a secret
// value.
func initSecrets(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init-secrets", flag.ContinueOnError)
	envPath := fs.String("env", ".env", "path to the .env file to create or complete")
	examplePath := fs.String("example", ".env.example", "path to the .env template")
	if err := fs.Parse(args); err != nil {
		return err
	}

	entries, err := envfile.Load(*envPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", *envPath, err)
	}
	if entries == nil {
		// Fresh file: seed from the example so keys, comments, and order carry over.
		entries, err = envfile.Load(*examplePath)
		if err != nil {
			return fmt.Errorf("read %s: %w", *examplePath, err)
		}
	}

	out, generated, kept, err := ensureSecrets(entries)
	if err != nil {
		return err
	}

	if err := envfile.WriteAtomic(*envPath, envfile.Render(out), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *envPath, err)
	}

	if _, err := fmt.Fprintf(stdout, "init-secrets: %d generated, %d kept — %s ready\n", generated, kept, *envPath); err != nil {
		return err
	}
	if databasePasswordsDiverge(out) {
		// Names only, never values.
		if _, err := fmt.Fprintln(stderr, "init-secrets: warning: POSTGRES_PASSWORD and PACKMON_DB_PASSWORD are both set and differ; "+
			"a fresh bundled PostgreSQL is initialized with POSTGRES_PASSWORD and will reject the server login "+
			"unless that database role was configured separately"); err != nil {
			return err
		}
	}
	return nil
}

// databasePasswordsDiverge reports whether both halves of the database
// password pair are set to different values. ensureSecrets never overwrites
// explicit values, so this can only come from operator input.
func databasePasswordsDiverge(entries []envfile.Entry) bool {
	pg, _ := envfile.Value(entries, "POSTGRES_PASSWORD")
	db, _ := envfile.Value(entries, "PACKMON_DB_PASSWORD")
	return !envfile.IsBlank(pg) && !envfile.IsBlank(db) && strings.TrimSpace(pg) != strings.TrimSpace(db)
}

// databasePasswordPartner returns the other key of the database password
// pair. The local Compose stack initializes the bundled PostgreSQL with
// POSTGRES_PASSWORD and connects with PACKMON_DB_PASSWORD, so a blank half must
// copy the other instead of getting a freshly generated, divergent value.
func databasePasswordPartner(key string) (string, bool) {
	switch key {
	case "POSTGRES_PASSWORD":
		return "PACKMON_DB_PASSWORD", true
	case "PACKMON_DB_PASSWORD":
		return "POSTGRES_PASSWORD", true
	default:
		return "", false
	}
}

// ensureSecrets fills missing/empty required secrets. A blank half of the
// database password pair mirrors the non-blank other half (in either
// direction); when both are blank one value is generated and shared. Existing
// non-empty values are preserved.
func ensureSecrets(entries []envfile.Entry) (out []envfile.Entry, generated, kept int, err error) {
	out = entries
	for _, s := range config.RequiredSecrets() {
		current, _ := envfile.Value(out, s.Key)
		if !envfile.IsBlank(current) {
			kept++
			continue
		}
		var value string
		if partner, paired := databasePasswordPartner(s.Key); paired {
			if other, ok := envfile.Value(out, partner); ok && !envfile.IsBlank(other) {
				value = other
			}
		}
		if value == "" {
			value, err = s.Generate()
			if err != nil {
				return nil, 0, 0, err
			}
			generated++
		}
		out = envfile.Upsert(out, s.Key, value)
	}
	return out, generated, kept, nil
}
