package main

import (
	"fmt"
	"os"

	"github.com/skaldlab/muninn/internal/normalizer"
)

const (
	localSARIFPath = "muninn.sarif"
	localJSONPath  = "muninn.json"
)

// findingCounts holds severity totals for GitHub Action outputs.
type findingCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// resolveOutputPaths returns SARIF and JSON paths for the current environment.
// The Docker action sets OUTPUT_PATH to muninn.sarif in the workspace mount so
// upload steps on the runner host can read the generated reports.
func resolveOutputPaths() (sarifPath, jsonPath string) {
	if sarif := os.Getenv("OUTPUT_PATH"); sarif != "" {
		json := os.Getenv("JSON_PATH")
		if json == "" {
			json = localJSONPath
		}
		return sarif, json
	}
	return localSARIFPath, localJSONPath
}

// countActiveFindings tallies non-suppressed findings by severity.
func countActiveFindings(findings []normalizer.Finding) findingCounts {
	var c findingCounts
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		c.Total++
		switch f.Severity {
		case normalizer.SeverityCritical:
			c.Critical++
		case normalizer.SeverityHigh:
			c.High++
		case normalizer.SeverityMedium:
			c.Medium++
		case normalizer.SeverityLow:
			c.Low++
		}
	}
	return c
}

// writeGitHubOutputs appends Muninn result metadata to the GITHUB_OUTPUT file
// so composite action steps can reference findings counts and report paths.
func writeGitHubOutputs(counts findingCounts, sarifPath, jsonPath string) error {
	outputPath := os.Getenv("GITHUB_OUTPUT")
	if outputPath == "" {
		return nil
	}
	f, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("opening GITHUB_OUTPUT: %w", err)
	}
	defer f.Close()

	pairs := []struct{ name, value string }{
		{"findings-count", fmt.Sprintf("%d", counts.Total)},
		{"critical-count", fmt.Sprintf("%d", counts.Critical)},
		{"high-count", fmt.Sprintf("%d", counts.High)},
		{"medium-count", fmt.Sprintf("%d", counts.Medium)},
		{"low-count", fmt.Sprintf("%d", counts.Low)},
		{"sarif-path", sarifPath},
		{"json-path", jsonPath},
	}
	for _, p := range pairs {
		if _, err := fmt.Fprintf(f, "%s=%s\n", p.name, p.value); err != nil {
			return fmt.Errorf("writing output %q: %w", p.name, err)
		}
	}
	return nil
}
