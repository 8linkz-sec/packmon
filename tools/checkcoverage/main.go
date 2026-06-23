package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	profile := flag.String("profile", "coverage.out", "coverage profile path")
	minimum := flag.Float64("min", 0, "minimum total statement coverage percentage")
	flag.Parse()

	if err := checkCoverage(*profile, *minimum); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	coverage, err := coveragePercentFromProfile(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("coverage %.1f%% meets required %.1f%%\n", coverage, *minimum)
}

func checkCoverage(profile string, minimum float64) error {
	coverage, err := coveragePercentFromProfile(profile)
	if err != nil {
		return err
	}
	if coverage+0.00001 < minimum {
		return fmt.Errorf("coverage %.1f%% is below required %.1f%%", coverage, minimum)
	}
	return nil
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
