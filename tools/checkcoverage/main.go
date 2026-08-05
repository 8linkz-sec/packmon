package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run holds the whole command so the gate itself is testable. It returns the
// process exit code instead of calling os.Exit, and writes through the supplied
// streams rather than the process ones.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("checkcoverage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profile := flags.String("profile", "coverage.out", "coverage profile path")
	minimum := flags.Float64("min", 0, "minimum total statement coverage percentage")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	coverage, err := checkCoverage(*profile, *minimum)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "coverage %.1f%% meets required %.1f%%\n", coverage, *minimum)
	return 0
}

// coverageEpsilon absorbs float rounding so a profile that is exactly at the
// threshold is not rejected by a trailing binary fraction.
const coverageEpsilon = 0.00001

// checkCoverage reads the profile once and returns the measured coverage
// together with the verdict, so callers do not have to re-read the file to
// report the value.
func checkCoverage(profile string, minimum float64) (float64, error) {
	coverage, err := coveragePercentFromProfile(profile)
	if err != nil {
		return 0, err
	}
	if coverage+coverageEpsilon < minimum {
		return coverage, fmt.Errorf("coverage %.1f%% is below required %.1f%%", coverage, minimum)
	}
	return coverage, nil
}

func coveragePercentFromProfile(profile string) (float64, error) {
	file, err := os.Open(profile) // #nosec G304 -- CI passes the just-generated local coverage profile path.
	if err != nil {
		return 0, fmt.Errorf("open coverage profile: %w", err)
	}
	defer func() { _ = file.Close() }()

	var totalStatements, coveredStatements int64
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// npm packages can ship Go source (for example flatted); that code is
		// not part of Packmon and must not skew the gate.
		if strings.Contains(line, "/node_modules/") {
			continue
		}
		statements, count, err := parseCoverageLine(line)
		if err != nil {
			return 0, fmt.Errorf("parse coverage profile line %d: %w", lineNumber, err)
		}
		totalStatements += statements
		if count > 0 {
			coveredStatements += statements
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read coverage profile: %w", err)
	}
	if totalStatements == 0 {
		return 0, errors.New("coverage profile has no statements")
	}
	return float64(coveredStatements) / float64(totalStatements) * 100, nil
}

func parseCoverageLine(line string) (statements, count int64, err error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return 0, 0, fmt.Errorf("expected 3 fields, got %d", len(fields))
	}
	statements, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("statement count: %w", err)
	}
	count, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("execution count: %w", err)
	}
	if statements < 0 || count < 0 {
		return 0, 0, errors.New("negative statement or execution count")
	}
	return statements, count, nil
}
