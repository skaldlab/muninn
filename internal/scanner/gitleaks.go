package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// gitleaksOutput mirrors one entry in gitleaks' JSON report.
// Field names match gitleaks' PascalCase JSON keys exactly so json.Unmarshal
// needs no custom tag remapping.
type gitleaksOutput struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	StartColumn int     `json:"StartColumn"`
	File        string  `json:"File"`
	RuleID      string  `json:"RuleID"`
	Fingerprint string  `json:"Fingerprint"`
	Secret      string  `json:"Secret"`
	Entropy     float64 `json:"Entropy"`
	Match       string  `json:"Match"`
}

// Gitleaks wraps the gitleaks secrets-detection binary.
// See: https://github.com/gitleaks/gitleaks
type Gitleaks struct {
	// execFunc creates the exec.Cmd for the gitleaks subprocess.
	// Tests inject a fake that writes fixture JSON to --report-path without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing gitleaks.
	lookPath func(string) (string, error)
}

// NewGitleaks returns a Gitleaks scanner ready for production use.
func NewGitleaks() *Gitleaks {
	return &Gitleaks{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (g *Gitleaks) Name() string { return "gitleaks" }

// IsAvailable implements Scanner.
func (g *Gitleaks) IsAvailable() bool {
	_, err := g.lookPath("gitleaks")
	return err == nil
}

// Configure implements Scanner. Gitleaks has no configurable options.
func (g *Gitleaks) Configure(_ config.ScannerConfig) {}

// Run implements Scanner.
func (g *Gitleaks) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gitleaks: binary not found on PATH")
	}
	raw, err := g.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeGitleaks(raw), nil
}

// execute creates a temp file for the report, runs the gitleaks subprocess,
// and parses the result. Exit code 1 is treated as success (leaks found, not a crash).
func (g *Gitleaks) execute(ctx context.Context, target string) ([]gitleaksOutput, error) {
	tmp, err := os.CreateTemp("", "muninn-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("gitleaks: creating temp report: %w", err)
	}
	reportPath := tmp.Name()
	tmp.Close()
	defer os.Remove(reportPath)

	cmd := g.execFunc(ctx, "gitleaks",
		"detect",
		"--source", target,
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-git",
	)
	if err := cmd.Run(); err != nil && !isGitleaksLeakFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("gitleaks: %w", ctx.Err())
		}
		return nil, fmt.Errorf("gitleaks: running scanner: %w", err)
	}
	return readGitleaksReport(reportPath)
}

// readGitleaksReport reads and parses the JSON report file written by gitleaks.
func readGitleaksReport(path string) ([]gitleaksOutput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: reading report: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var out []gitleaksOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("gitleaks: parsing report JSON: %w", err)
	}
	return out, nil
}

// normalizeGitleaks converts raw gitleaks output to the unified Finding schema.
func normalizeGitleaks(raw []gitleaksOutput) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(raw))
	for _, r := range raw {
		out = append(out, normalizeOneGitleaks(r))
	}
	return out
}

// normalizeOneGitleaks maps a single gitleaks entry to a Finding.
func normalizeOneGitleaks(r gitleaksOutput) normalizer.Finding {
	fp := r.Fingerprint
	if fp == "" {
		fp = gitleaksFingerprint(r.File, r.StartLine, r.RuleID)
	}
	return normalizer.Finding{
		ID:          fp,
		Tool:        "gitleaks",
		Severity:    gitleaksSeverity(r.RuleID),
		Title:       r.Description,
		Description: fmt.Sprintf("Secret detected in %s (rule: %s)", r.File, r.RuleID),
		File:        r.File,
		Line:        r.StartLine,
		Column:      r.StartColumn,
		RuleID:      r.RuleID,
		RuleURL:     "https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml",
		Fingerprint: fp,
		Metadata: map[string]any{
			"entropy": r.Entropy,
			"match":   r.Match,
		},
	}
}

// gitleaksSeverity derives a severity level from the rule ID.
// Gitleaks does not include severity in its JSON output, so we infer it from
// keywords in the rule name: well-known cloud/infra credential rules are
// critical; generic password/token rules are high; everything else is medium.
func gitleaksSeverity(ruleID string) normalizer.Severity {
	rule := strings.ToLower(ruleID)
	for _, kw := range []string{
		"private-key", "aws", "gcp", "azure",
		"github-token", "slack-token", "stripe", "twilio", "sendgrid",
	} {
		if strings.Contains(rule, kw) {
			return normalizer.SeverityCritical
		}
	}
	for _, kw := range []string{"password", "secret", "api-key", "token"} {
		if strings.Contains(rule, kw) {
			return normalizer.SeverityHigh
		}
	}
	return normalizer.SeverityMedium
}

// gitleaksFingerprint returns the first 16 hex chars of SHA-256(tool:file:line:ruleID).
// Used when gitleaks itself does not supply a fingerprint.
func gitleaksFingerprint(file string, line int, ruleID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("gitleaks:%s:%d:%s", file, line, ruleID)))
	return fmt.Sprintf("%x", sum[:8])
}

// isGitleaksLeakFound reports whether err is an exit-code-1 from gitleaks,
// which means the scan completed successfully and found secrets — not a crash.
func isGitleaksLeakFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
