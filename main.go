// Muninn is an open source security scanner for GitHub Actions pipelines.
// It orchestrates multiple scanning tools, normalizes their output into a
// unified finding schema, and reports results as PR comments, SARIF, and JSON.
//
// Named after Odin's raven of Memory — Muninn remembers every vulnerability
// it has ever seen.
//
// Usage:
//
//	muninn [flags]
//
// Flags:
//
//	--config    path to muninn.yml (default: muninn.yml, env: CONFIG_PATH)
//	--target    path to repository root to scan (default: ., env: SCAN_TARGET)
//	--fail-on   minimum severity to exit non-zero (default: critical, env: FAIL_ON)
//	--output    comma-separated output formats: json,sarif,comment (env: OUTPUT_FORMATS)
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/reporter"
	"github.com/skaldlab/muninn/internal/scanner"
)

const (
	sarifOutputFile = "muninn.sarif"
	jsonOutputFile  = "muninn.json"
)

func main() {
	os.Exit(run())
}

// run is the real entry point, separated from main so deferred calls and
// explicit exit codes work correctly together.
func run() int {
	fs := flag.NewFlagSet("muninn", flag.ContinueOnError)

	configPath := fs.String("config", envOr("CONFIG_PATH", "muninn.yml"), "path to muninn.yml config file")
	target := fs.String("target", envOr("SCAN_TARGET", "."), "path to repository root to scan")
	failOn := fs.String("fail-on", envOr("FAIL_ON", ""), "minimum severity to fail the check (overrides config)")
	output := fs.String("output", envOr("OUTPUT_FORMATS", "json"), "comma-separated output formats: json,sarif,comment")
	format := fs.String("format", "", "output format (sarif, json, comment) — overrides --output when set")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		cfg = config.Defaults()
	}

	if *failOn != "" {
		cfg.FailOn = *failOn
	}

	selectedFormats := *output
	if *format != "" {
		selectedFormats = *format
	}

	if err := scan(ctx, cfg, *target, selectedFormats); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 1
	}

	return 0
}

// scan orchestrates all enabled scanners against target, writes the requested
// report formats, and enforces the fail-on threshold.
func scan(ctx context.Context, cfg *config.Config, target, outputFormats string) error {
	fmt.Printf("muninn: scanning %s (formats=%s, fail-on=%s)\n", target, outputFormats, cfg.FailOn)

	var findings []normalizer.Finding
	for _, sc := range activeScanners() {
		findings = append(findings, runScanner(ctx, sc, target, cfg)...)
	}

	for _, format := range splitFormats(outputFormats) {
		if err := writeReport(ctx, format, findings); err != nil {
			return err
		}
	}

	return checkFailOn(cfg.FailOn, findings)
}

// activeScanners returns the ordered list of every scanner Muninn knows about.
// Order determines the sequence in which scanners run and findings are reported.
func activeScanners() []scanner.Scanner {
	return []scanner.Scanner{
		scanner.NewGitleaks(),
		scanner.NewZizmor(),
		scanner.NewActionlint(),
		scanner.NewPoutine(),
		scanner.NewSemgrep(),
		scanner.NewOSVScanner(),
		scanner.NewTrivy(),
		scanner.NewCheckov(),
	}
}

// runScanner executes a single scanner when it is enabled in cfg and present on
// PATH. Scanner-level failures are logged and swallowed so one broken tool does
// not abort the whole run; only the produced findings are returned.
func runScanner(ctx context.Context, sc scanner.Scanner, target string, cfg *config.Config) []normalizer.Finding {
	name := sc.Name()
	if c, ok := cfg.Scanners[name]; ok && !c.Enabled {
		fmt.Printf("muninn: %s disabled in config, skipping\n", name)
		return nil
	}
	if !sc.IsAvailable() {
		fmt.Printf("muninn: %s not found, skipping\n", name)
		return nil
	}
	found, err := sc.Run(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %s: %v\n", name, err)
		return nil
	}
	fmt.Printf("muninn: %s: %d finding(s)\n", name, len(found))
	return found
}

// writeReport writes findings in a single output format. Unknown formats are
// ignored so a typo in the --output flag does not abort the run.
func writeReport(ctx context.Context, format string, findings []normalizer.Finding) error {
	switch format {
	case "sarif":
		if err := writeSARIF(sarifOutputFile, findings); err != nil {
			return fmt.Errorf("writing SARIF output: %w", err)
		}
		fmt.Println("muninn: wrote " + sarifOutputFile)
	case "json":
		if err := writeJSON(jsonOutputFile, findings); err != nil {
			return fmt.Errorf("writing JSON output: %w", err)
		}
		fmt.Println("muninn: wrote " + jsonOutputFile)
	case "comment":
		rep := &reporter.Comment{}
		if err := rep.Write(ctx, os.Stdout, findings); err != nil {
			return fmt.Errorf("writing comment output: %w", err)
		}
	}
	return nil
}

// checkFailOn returns a non-nil error when any non-suppressed finding meets or
// exceeds the threshold severity. An empty threshold disables the check.
func checkFailOn(threshold string, findings []normalizer.Finding) error {
	if threshold == "" {
		return nil
	}
	limit := severityRank(normalizer.Severity(threshold))
	count := 0
	for _, f := range findings {
		if !f.Suppressed && severityRank(f.Severity) >= limit {
			count++
		}
	}
	if count > 0 {
		return fmt.Errorf("found %d finding(s) at or above %q severity", count, threshold)
	}
	return nil
}

// severityRank maps a severity to a comparable integer so thresholds can be
// evaluated with a simple >= comparison. Higher means more severe.
func severityRank(s normalizer.Severity) int {
	switch s {
	case normalizer.SeverityCritical:
		return 5
	case normalizer.SeverityHigh:
		return 4
	case normalizer.SeverityMedium:
		return 3
	case normalizer.SeverityLow:
		return 2
	case normalizer.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// writeSARIF writes a SARIF 2.1.0 document to path via the SARIF reporter.
// When findings is empty, a valid skeleton with zero results is written so that
// the github/codeql-action/upload-sarif step does not error on a missing file.
func writeSARIF(path string, findings []normalizer.Finding) error {
	return writeToFile(path, func(w io.Writer) error {
		return (&reporter.SARIF{}).Write(context.Background(), w, findings)
	})
}

// writeJSON writes findings as a JSON array to path using the JSON reporter.
func writeJSON(path string, findings []normalizer.Finding) error {
	return writeToFile(path, func(w io.Writer) error {
		return (&reporter.JSON{}).Write(context.Background(), w, findings)
	})
}

// writeToFile creates path and hands the open file to fn, ensuring it is closed
// afterwards. It centralizes the create/close boilerplate for reporters that
// write to an io.Writer.
func writeToFile(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return fn(f)
}

// envOr returns the value of the environment variable key, or fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitFormats splits a comma-separated format string and trims whitespace.
func splitFormats(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
