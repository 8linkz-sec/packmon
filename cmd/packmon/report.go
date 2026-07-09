package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

var reportSeverityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

type reportCommandOptions struct {
	repo  string
	limit int
}

type reportCommandDeps struct {
	resolveDBPath func() (string, error)
	openStore     func(string) (reportScanStore, error)
	output        io.Writer
}

type reportScanStore interface {
	GetRecentScans(context.Context, string, int) ([]sqlite.ScanEntry, error)
	Close() error
}

type reportSummary struct {
	TotalScans     int
	TotalPackages  int
	TotalFindings  int
	SeverityCounts map[string]int
}

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
			return runReportCommand(c.Context(), reportCommandOptions{
				repo:  flagRepo,
				limit: flagLimit,
			}, defaultReportCommandDeps())
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagRepo, "repo", "", "filter by repository name")
	f.IntVar(&flagLimit, "limit", 20, "number of recent scans to show")

	return cmd
}

func defaultReportCommandDeps() reportCommandDeps {
	return reportCommandDeps{
		resolveDBPath: resolveLocalDBPath,
		openStore: func(path string) (reportScanStore, error) {
			return sqlite.New(path)
		},
		output: os.Stdout,
	}
}

func runReportCommand(ctx context.Context, opts reportCommandOptions, deps reportCommandDeps) error {
	if deps.resolveDBPath == nil {
		deps.resolveDBPath = resolveLocalDBPath
	}
	if deps.openStore == nil {
		deps.openStore = func(path string) (reportScanStore, error) {
			return sqlite.New(path)
		}
	}
	if deps.output == nil {
		deps.output = os.Stdout
	}

	dbPath, err := deps.resolveDBPath()
	if err != nil {
		return err
	}
	store, err := deps.openStore(dbPath)
	if err != nil {
		return fmt.Errorf("open local database: %w", err)
	}
	defer ioutils.CloseSilently(store)

	entries, err := store.GetRecentScans(ctx, opts.repo, opts.limit)
	if err != nil {
		return fmt.Errorf("read scan history: %w", err)
	}

	return writeReportOutput(deps.output, opts.repo, entries)
}

func summarizeReportEntries(entries []sqlite.ScanEntry) reportSummary {
	summary := reportSummary{
		TotalScans:     len(entries),
		SeverityCounts: make(map[string]int, len(reportSeverityOrder)),
	}
	for _, sev := range reportSeverityOrder {
		summary.SeverityCounts[sev] = 0
	}
	for _, entry := range entries {
		summary.TotalFindings += entry.FindingsCount
		summary.TotalPackages += entry.PackagesCount
		for _, sev := range entry.FindingSeverities {
			summary.SeverityCounts[sev]++
		}
	}
	return summary
}

func writeReportOutput(output io.Writer, repo string, entries []sqlite.ScanEntry) error {
	if output == nil {
		output = os.Stdout
	}
	if len(entries) == 0 {
		fmt.Fprintln(output, "No scan history found.")
		if repo != "" {
			fmt.Fprintf(output, "  (filtered by repo: %s)\n", termtext.Sanitize(repo))
		}
		fmt.Fprintln(output, "Run 'packmon scan' to generate scan data.")
		return nil
	}

	fmt.Fprintf(output, "\nPackmon Security Report")
	if repo != "" {
		fmt.Fprintf(output, " -- %s", termtext.Sanitize(repo))
	}
	fmt.Fprintf(output, "\n%s\n\n", strings.Repeat("=", 60))

	summary := summarizeReportEntries(entries)
	fmt.Fprintf(output, "Scans:     %d\n", summary.TotalScans)
	fmt.Fprintf(output, "Packages:  %d (total across scans)\n", summary.TotalPackages)
	fmt.Fprintf(output, "Findings:  %d (total across scans)\n", summary.TotalFindings)
	fmt.Fprintln(output)

	fmt.Fprintln(output, "Severity Distribution")
	fmt.Fprintln(output, strings.Repeat("-", 30))
	for _, sev := range reportSeverityOrder {
		count := summary.SeverityCounts[sev]
		if count > 0 {
			fmt.Fprintf(output, "  %-10s %d\n", sev, count)
		}
	}
	fmt.Fprintln(output)

	fmt.Fprintln(output, "Recent Scans")
	fmt.Fprintln(output, strings.Repeat("-", 60))
	if err := writeReportTable(output, entries); err != nil {
		return err
	}
	fmt.Fprintln(output)

	return nil
}

func writeReportTable(output io.Writer, entries []sqlite.ScanEntry) error {
	if output == nil {
		output = os.Stdout
	}
	tw := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DATE\tREPO\tPACKAGES\tFINDINGS\tTREND"); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}

	for i, entry := range entries {
		repo := entry.RepoName
		if repo == "" {
			repo = "(local)"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n",
			formatReportTimestamp(entry.ScannedAt),
			termtext.Sanitize(repo),
			entry.PackagesCount,
			entry.FindingsCount,
			reportEntryTrend(entries, i)); err != nil {
			return fmt.Errorf("write report row: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush report output: %w", err)
	}
	return nil
}

func reportEntryTrend(entries []sqlite.ScanEntry, i int) string {
	if i+1 >= len(entries) {
		return " "
	}
	current := entries[i]
	previous := entries[i+1]
	if current.FindingsCount > previous.FindingsCount {
		return "^ +" + fmt.Sprintf("%d", current.FindingsCount-previous.FindingsCount)
	}
	if current.FindingsCount < previous.FindingsCount {
		return "v " + fmt.Sprintf("%d", previous.FindingsCount-current.FindingsCount)
	}
	return "= 0"
}
