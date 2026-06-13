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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/scanner"
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

	if err := scan(ctx, cfg, *target, *output); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: %v\n", err)
		return 1
	}

	return 0
}

// scan orchestrates all enabled scanners against target and writes the report.
func scan(ctx context.Context, cfg *config.Config, target, outputFormats string) error {
	fmt.Printf("muninn: scanning %s (formats=%s, fail-on=%s)\n", target, outputFormats, cfg.FailOn)

	var findings []normalizer.Finding

	gl := scanner.NewGitleaks()
	if gl.IsAvailable() {
		glFindings, err := gl.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "muninn: gitleaks: %v\n", err)
		} else {
			findings = append(findings, glFindings...)
			fmt.Printf("muninn: gitleaks: %d finding(s)\n", len(glFindings))
		}
	} else {
		fmt.Println("muninn: gitleaks not found, skipping")
	}

	zz := scanner.NewZizmor()
	if zz.IsAvailable() {
		zzFindings, err := zz.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "muninn: zizmor: %v\n", err)
		} else {
			findings = append(findings, zzFindings...)
			fmt.Printf("muninn: zizmor: %d finding(s)\n", len(zzFindings))
		}
	} else {
		fmt.Println("muninn: zizmor not found, skipping")
	}

	al := scanner.NewActionlint()
	if al.IsAvailable() {
		alFindings, err := al.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "muninn: actionlint: %v\n", err)
		} else {
			findings = append(findings, alFindings...)
			fmt.Printf("muninn: actionlint: %d finding(s)\n", len(alFindings))
		}
	} else {
		fmt.Println("muninn: actionlint not found, skipping")
	}

	po := scanner.NewPoutine()
	if po.IsAvailable() {
		poFindings, err := po.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "muninn: poutine: %v\n", err)
		} else {
			findings = append(findings, poFindings...)
			fmt.Printf("muninn: poutine: %d finding(s)\n", len(poFindings))
		}
	} else {
		fmt.Println("muninn: poutine not found, skipping")
	}

	sg := scanner.NewSemgrep()
	if sg.IsAvailable() {
		sgFindings, err := sg.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "muninn: semgrep: %v\n", err)
		} else {
			findings = append(findings, sgFindings...)
			fmt.Printf("muninn: semgrep: %d finding(s)\n", len(sgFindings))
		}
	} else {
		fmt.Println("muninn: semgrep not found, skipping")
	}

	formats := splitFormats(outputFormats)
	for _, fmt_ := range formats {
		switch fmt_ {
		case "sarif":
			if err := writeSARIF("muninn.sarif", findings); err != nil {
				return fmt.Errorf("writing SARIF output: %w", err)
			}
			fmt.Println("muninn: wrote muninn.sarif")
		case "json":
			if err := writeJSON("muninn.json", findings); err != nil {
				return fmt.Errorf("writing JSON output: %w", err)
			}
			fmt.Println("muninn: wrote muninn.json")
		case "comment":
			// TODO: post GitHub PR comment via GitHub API
			fmt.Println("muninn: PR comment reporter not yet implemented")
		}
	}

	// TODO: evaluate cfg.FailOn against findings and return a sentinel error
	//       when critical/high/etc. findings exceed the threshold.
	return nil
}

// writeSARIF writes a SARIF 2.1.0 document to path.
// When findings is empty, a valid skeleton with zero results is written so that
// the github/codeql-action/upload-sarif step does not error on a missing file.
func writeSARIF(path string, findings []normalizer.Finding) error {
	type sarifLocation struct {
		ArtifactLocation struct {
			URI   string `json:"uri"`
			Index int    `json:"index"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn,omitempty"`
		} `json:"region"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation sarifLocation `json:"physicalLocation"`
		} `json:"locations"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				InformationURI string `json:"informationUri"`
				Rules          []any  `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	// GitHub's upload-sarif endpoint requires at least one run object, even when
	// there are zero findings. Always emit a single Muninn run with an empty (but
	// non-null) results array.
	run := sarifRun{Results: []sarifResult{}}
	run.Tool.Driver.Name = "Muninn"
	run.Tool.Driver.InformationURI = "https://github.com/skaldlab/muninn"
	run.Tool.Driver.Rules = []any{}

	// TODO: append a sarifResult per finding once scanner implementations land.
	_ = findings

	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling SARIF: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// writeJSON writes findings as a JSON array to path.
func writeJSON(path string, findings []normalizer.Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling findings: %w", err)
	}
	return os.WriteFile(path, data, 0644)
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
