package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/envfile"
)

// runInitSecrets generates any missing/empty required secrets into a .env file,
// seeding a fresh file from .env.example. Existing non-empty values are never
// overwritten. It never prints secret values.
func runInitSecrets(args []string) error {
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

	fmt.Fprintf(os.Stdout, "init-secrets: %d generated, %d kept — %s ready\n", generated, kept, *envPath)
	return nil
}

// ensureSecrets fills missing/empty required secrets, mirroring PACKMON_DB_PASSWORD
// onto POSTGRES_PASSWORD when the DB password is blank. Existing non-empty values
// are preserved.
func ensureSecrets(entries []envfile.Entry) (out []envfile.Entry, generated, kept int, err error) {
	out = entries
	for _, s := range config.RequiredSecrets() {
		current, _ := envfile.Value(out, s.Key)
		if !envfile.IsBlank(current) {
			kept++
			continue
		}
		var value string
		if s.Key == "PACKMON_DB_PASSWORD" {
			if pg, ok := envfile.Value(out, "POSTGRES_PASSWORD"); ok && !envfile.IsBlank(pg) {
				value = pg
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
