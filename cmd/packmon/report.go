package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		flagRepo  string
		flagLimit int
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate security report from scan history",
		Long: `Display a terminal report of recent scans including finding counts,
severity distribution, and trend over time. Data is read from the local
SQLite scan history.`,
		RunE: func(c *cobra.Command, _ []string) error {
			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}
			store, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer closeSilently(store)

			ctx := c.Context()
			entries, err := store.GetRecentScans(ctx, flagRepo, flagLimit)
			if err != nil {
				return fmt.Errorf("read scan history: %w", err)
			}

			if len(entries) == 0 {
				fmt.Println("No scan history found.")
				if flagRepo != "" {
					fmt.Printf("  (filtered by repo: %s)\n", termtext.Sanitize(flagRepo))
				}
				fmt.Println("Run 'packmon scan' to generate scan data.")
				return nil
			}

			// Print header.
			fmt.Printf("\nPackmon Security Report")
			if flagRepo != "" {
				fmt.Printf(" -- %s", termtext.Sanitize(flagRepo))
			}
			fmt.Printf("\n%s\n\n", strings.Repeat("=", 60))

			// Summary statistics across all returned entries.
			totalScans := len(entries)
			totalFindings := 0
			totalPackages := 0
			sevCounts := map[string]int{
				"CRITICAL": 0,
				"HIGH":     0,
				"MEDIUM":   0,
				"LOW":      0,
				"UNKNOWN":  0,
			}

			for _, e := range entries {
				totalFindings += e.FindingsCount
				totalPackages += e.PackagesCount
				for _, sev := range e.FindingSeverities {
					sevCounts[sev]++
				}
			}

			fmt.Printf("Scans:     %d\n", totalScans)
			fmt.Printf("Packages:  %d (total across scans)\n", totalPackages)
			fmt.Printf("Findings:  %d (total across scans)\n", totalFindings)
			fmt.Println()

			// Severity distribution.
			fmt.Println("Severity Distribution")
			fmt.Println(strings.Repeat("-", 30))
			for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
				count := sevCounts[sev]
				if count > 0 {
					fmt.Printf("  %-10s %d\n", sev, count)
				}
			}
			fmt.Println()

			// Trend: show the last N scans with finding counts.
			fmt.Println("Recent Scans")
			fmt.Println(strings.Repeat("-", 60))

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "DATE\tREPO\tPACKAGES\tFINDINGS\tTREND"); err != nil {
				return fmt.Errorf("write report header: %w", err)
			}

			for i, e := range entries {
				dateStr := formatReportTimestamp(e.ScannedAt)
				repo := e.RepoName
				if repo == "" {
					repo = "(local)"
				}
				repo = termtext.Sanitize(repo)

				// Compute simple trend indicator vs. next older scan.
				trend := " "
				if i+1 < len(entries) {
					prev := entries[i+1]
					if e.FindingsCount > prev.FindingsCount {
						trend = "^ +" + fmt.Sprintf("%d", e.FindingsCount-prev.FindingsCount)
					} else if e.FindingsCount < prev.FindingsCount {
						trend = "v " + fmt.Sprintf("%d", prev.FindingsCount-e.FindingsCount)
					} else {
						trend = "= 0"
					}
				}

				if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n",
					dateStr, repo, e.PackagesCount, e.FindingsCount, trend); err != nil {
					return fmt.Errorf("write report row: %w", err)
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("flush report output: %w", err)
			}
			fmt.Println()

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagRepo, "repo", "", "filter by repository name")
	f.IntVar(&flagLimit, "limit", 20, "number of recent scans to show")

	return cmd
}
