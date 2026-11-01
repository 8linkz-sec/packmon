package main

import (
	"flag"
	"fmt"

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

	fmt.Printf("init-secrets: %d generated, %d kept — %s ready\n", generated, kept, *envPath)
	return nil
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
