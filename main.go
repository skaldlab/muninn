// Muninn is an open source security scanner for GitHub Actions pipelines.
// It orchestrates multiple scanning tools, normalizes their output into a
// unified finding schema, and reports results as PR comments, SARIF, and JSON.
//
// Named after Odin's raven of Memory — Muninn remembers every vulnerability
// it has ever seen.
//
// Usage:
//
//	muninn scan [flags]
//
// Flags:
//
//	--config    path to muninn.yml (default: muninn.yml)
//	--target    path to repository root to scan (default: .)
//	--fail-on   minimum severity to exit non-zero (default: critical)
//	--output    output format: json, sarif, comment (default: json)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/skaldlab/muninn/internal/config"
)

func main() {
	os.Exit(run())
}

// run is the real entry point, separated from main so deferred calls and
// explicit exit codes work correctly together.
func run() int {
	fs := flag.NewFlagSet("muninn", flag.ContinueOnError)

	configPath := fs.String("config", "muninn.yml", "path to muninn.yml config file")
	target := fs.String("target", ".", "path to repository root to scan")
	failOn := fs.String("fail-on", "", "minimum severity to fail the check (overrides config)")
	output := fs.String("output", "json", "output format: json, sarif, comment")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// Config file missing is acceptable at this scaffold stage; use defaults.
		cfg, _ = config.Load("/dev/null")
		if cfg == nil {
			fmt.Fprintf(os.Stderr, "muninn: failed to load config: %v\n", err)
			return 1
		}
	}

	// CLI flag overrides config file value when provided.
	if *failOn != "" {
		cfg.FailOn = *failOn
	}

	if err := scan(ctx, cfg, *target, *output); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 1
	}

	return 0
}

// scan orchestrates all enabled scanners against target and writes the report.
func scan(ctx context.Context, cfg *config.Config, target, outputFormat string) error {
	// TODO: instantiate enabled scanners from cfg.Scanners
	// TODO: run each scanner concurrently, collecting []Finding
	// TODO: apply suppressions from cfg.Suppressions
	// TODO: route to reporter based on outputFormat
	// TODO: evaluate cfg.FailOn and return a sentinel error if threshold exceeded

	fmt.Printf("muninn: scanning %s (format=%s, fail-on=%s)\n", target, outputFormat, cfg.FailOn)
	fmt.Println("muninn: scaffold only — scanner implementations pending")

	return nil
}
