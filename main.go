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
//	--version   print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/reporter"
	"github.com/skaldlab/muninn/internal/scanner"
)

const (
	sarifOutputFile = localSARIFPath
	jsonOutputFile  = localJSONPath
	version         = "0.1.0"
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
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 2
	}

	if *showVersion {
		fmt.Printf("muninn %s\n", version)
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := loadConfig(*configPath, *target)

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

// loadConfig reads muninn.yml, trying target-relative paths before defaults.
// GitHub Actions docker runs may start with a working directory outside the
// checked-out repository, so muninn.yml is not always found on the first path.
func loadConfig(configPath, target string) *config.Config {
	if !filepath.IsAbs(target) {
		if abs, err := filepath.Abs(target); err == nil {
			target = abs
		}
	}
	paths := []string{configPath}
	if !filepath.IsAbs(configPath) {
		paths = append(paths, filepath.Join(target, configPath))
	}
	for _, p := range paths {
		if cfg, err := config.Load(p); err == nil {
			return cfg
		}
	}
	return config.Defaults()
}

// scan orchestrates all enabled scanners against target, writes the requested
// report formats, and enforces the fail-on threshold.
func scan(ctx context.Context, cfg *config.Config, target, outputFormats string) error {
	fmt.Printf("muninn: scanning %s (formats=%s, fail-on=%s)\n", target, outputFormats, cfg.FailOn)

	var findings []normalizer.Finding
	for _, sc := range activeScanners() {
		findings = append(findings, runScanner(ctx, sc, target, cfg)...)
	}

	findings = applySuppressions(findings, cfg.Suppressions)

	sarifPath, jsonPath := resolveOutputPaths()
	for _, format := range splitFormats(outputFormats) {
		if err := writeReport(ctx, format, findings, sarifPath, jsonPath); err != nil {
			return err
		}
	}

	counts := countActiveFindings(findings)
	if err := writeGitHubOutputs(counts, sarifPath, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: writing GitHub outputs: %v\n", err)
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
	scCfg, ok := cfg.Scanners[name]
	if ok && !scCfg.Enabled {
		fmt.Printf("muninn: %s disabled in config, skipping\n", name)
		return nil
	}
	sc.Configure(scCfg)
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
func writeReport(ctx context.Context, format string, findings []normalizer.Finding, sarifPath, jsonPath string) error {
	switch format {
	case "sarif":
		if err := writeSARIF(sarifPath, findings); err != nil {
			return fmt.Errorf("writing SARIF output: %w", err)
		}
		fmt.Println("muninn: wrote " + sarifPath)
	case "json":
		if err := writeJSON(jsonPath, findings); err != nil {
			return fmt.Errorf("writing JSON output: %w", err)
		}
		fmt.Println("muninn: wrote " + jsonPath)
	case "comment":
		body, err := renderComment(ctx, findings)
		if err != nil {
			return err
		}
		if err := postPRComment(ctx, body); err != nil {
			fmt.Fprintf(os.Stderr, "muninn: PR comment: %v\n", err)
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

// applySuppressions marks findings as suppressed when a matching, non-expired
// suppression rule exists. Suppressed findings are kept in the returned slice
// so that reporters can display them differently. The input slice is not
// mutated; a new slice is always returned.
func applySuppressions(findings []normalizer.Finding, suppressions []config.Suppression) []normalizer.Finding {
	if len(suppressions) == 0 {
		return findings
	}
	now := time.Now()
	out := make([]normalizer.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if isSuppressed(out[i], suppressions, now) {
			out[i].Suppressed = true
		}
	}
	return out
}

// isSuppressed returns true when f matches at least one active suppression
// rule. A suppression is active when its Expires field is zero or in the future.
func isSuppressed(f normalizer.Finding, suppressions []config.Suppression, now time.Time) bool {
	for _, s := range suppressions {
		if !suppressionActive(s, now) {
			continue
		}
		if s.ID != "" && strings.Contains(filepath.ToSlash(f.File), s.ID) {
			return true
		}
		if s.Fingerprint != "" && s.Fingerprint == f.Fingerprint {
			return true
		}
	}
	return false
}

// suppressionActive reports whether a suppression rule has not yet expired.
func suppressionActive(s config.Suppression, now time.Time) bool {
	return s.Expires.IsZero() || now.Before(s.Expires)
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
