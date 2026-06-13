package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// checkovCheck mirrors one entry in checkov's failed_checks array.
// Only fields Muninn needs are mapped; unknown fields are silently ignored.
type checkovCheck struct {
	CheckID     string `json:"check_id"`
	BCCheckID   string `json:"bc_check_id"`
	CheckName   string `json:"check_name"`
	FilePath    string `json:"file_path"`
	FileLineRange []int `json:"file_line_range"`
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Guideline   string `json:"guideline"`
}

// checkovResults holds the results block within a single checkov framework output.
type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

// checkovBlock represents one framework's output object.
type checkovBlock struct {
	CheckType string         `json:"check_type"`
	Results   checkovResults `json:"results"`
}

// Checkov wraps the Bridgecrew Checkov IaC misconfiguration scanner.
// See: https://github.com/bridgecrewio/checkov
type Checkov struct {
	// execFunc creates the exec.Cmd for the checkov subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing checkov.
	lookPath func(string) (string, error)
}

// NewCheckov returns a Checkov scanner ready for production use.
func NewCheckov() *Checkov {
	return &Checkov{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (c *Checkov) Name() string { return "checkov" }

// IsAvailable implements Scanner.
func (c *Checkov) IsAvailable() bool {
	_, err := c.lookPath("checkov")
	return err == nil
}

// Run implements Scanner.
func (c *Checkov) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("checkov: binary not found on PATH")
	}
	blocks, err := c.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeCheckov(blocks), nil
}

// execute runs the checkov subprocess and captures its JSON output from stdout.
// Exit code 1 means failed checks were found — not a crash.
func (c *Checkov) execute(ctx context.Context, target string) ([]checkovBlock, error) {
	cmd := c.execFunc(ctx, "checkov",
		"--directory", target,
		"--output", "json",
		"--quiet",
		"--compact",
	)
	out, err := cmd.Output()
	if err != nil && !isCheckovFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("checkov: %w", ctx.Err())
		}
		return nil, fmt.Errorf("checkov: running scanner: %w", err)
	}
	return parseCheckovJSON(out)
}

// parseCheckovJSON handles both the single-object and array forms that checkov
// can emit depending on the number of frameworks detected in the target.
func parseCheckovJSON(data []byte) ([]checkovBlock, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Detect array vs object by the first non-whitespace byte.
	for _, b := range data {
		if b == '[' {
			var blocks []checkovBlock
			if err := json.Unmarshal(data, &blocks); err != nil {
				return nil, fmt.Errorf("checkov: parsing JSON array: %w", err)
			}
			return blocks, nil
		}
		if b == '{' {
			var block checkovBlock
			if err := json.Unmarshal(data, &block); err != nil {
				return nil, fmt.Errorf("checkov: parsing JSON object: %w", err)
			}
			return []checkovBlock{block}, nil
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			break
		}
	}
	return nil, nil
}

// normalizeCheckov converts all failed_checks across all framework blocks
// into the unified Finding schema.
func normalizeCheckov(blocks []checkovBlock) []normalizer.Finding {
	var out []normalizer.Finding
	for _, block := range blocks {
		for _, check := range block.Results.FailedChecks {
			out = append(out, normalizeOneCheckov(block.CheckType, check))
		}
	}
	return out
}

// normalizeOneCheckov maps a single failed check to a Finding.
func normalizeOneCheckov(checkType string, check checkovCheck) normalizer.Finding {
	fp := checkovFingerprint(check.FilePath, check.CheckID, check.Resource)
	line := 0
	if len(check.FileLineRange) > 0 {
		line = check.FileLineRange[0]
	}
	return normalizer.Finding{
		ID:          fp,
		Tool:        "checkov",
		Severity:    checkovSeverity(check.Severity),
		Title:       check.CheckName,
		Description: check.CheckName,
		File:        check.FilePath,
		Line:        line,
		RuleID:      check.CheckID,
		RuleURL:     check.Guideline,
		Fingerprint: fp,
		Metadata: map[string]any{
			"resource":    check.Resource,
			"check_type":  checkType,
			"bc_check_id": check.BCCheckID,
		},
	}
}

// checkovSeverity maps a checkov severity string to a Muninn Severity.
func checkovSeverity(severity string) normalizer.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return normalizer.SeverityCritical
	case "HIGH":
		return normalizer.SeverityHigh
	case "MEDIUM":
		return normalizer.SeverityMedium
	case "LOW":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}

// checkovFingerprint returns the first 16 hex chars of
// SHA-256(checkov:filePath:checkID:resource).
func checkovFingerprint(filePath, checkID, resource string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("checkov:%s:%s:%s", filePath, checkID, resource)))
	return fmt.Sprintf("%x", sum[:8])
}

// isCheckovFindingsFound reports whether err is an exit-code-1 from checkov,
// which means the scan completed and found failures — not a crash.
func isCheckovFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
