package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// zizmorSARIF mirrors the subset of SARIF 2.1.0 that zizmor emits on stdout.
// Only the fields Muninn needs are mapped; unknown fields are silently ignored.
type zizmorSARIF struct {
	Runs []zizmorRun `json:"runs"`
}

type zizmorRun struct {
	Tool    zizmorTool     `json:"tool"`
	Results []zizmorResult `json:"results"`
}

type zizmorTool struct {
	Driver zizmorDriver `json:"driver"`
}

type zizmorDriver struct {
	Rules []zizmorRule `json:"rules"`
}

type zizmorRule struct {
	ID      string `json:"id"`
	HelpURI string `json:"helpUri"`
	// DefaultConfiguration carries the rule-level severity but zizmor also
	// sets per-result level, so we use the result level for normalization.
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type zizmorResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      zizmorMessage     `json:"message"`
	Locations    []zizmorLocation  `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints"`
}

type zizmorMessage struct {
	Text string `json:"text"`
}

type zizmorLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// Zizmor wraps the zizmor CI/CD pipeline security scanner.
// See: https://github.com/woodruffw/zizmor
type Zizmor struct {
	// execFunc creates the exec.Cmd for the zizmor subprocess.
	// Tests inject a fake that writes fixture SARIF to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing zizmor.
	lookPath func(string) (string, error)
}

// NewZizmor returns a Zizmor scanner ready for production use.
func NewZizmor() *Zizmor {
	return &Zizmor{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (z *Zizmor) Name() string { return "zizmor" }

// IsAvailable implements Scanner.
func (z *Zizmor) IsAvailable() bool {
	_, err := z.lookPath("zizmor")
	return err == nil
}

// Configure implements Scanner. Zizmor has no configurable options.
func (z *Zizmor) Configure(_ config.ScannerConfig) {}

// Run implements Scanner.
func (z *Zizmor) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !z.IsAvailable() {
		return nil, fmt.Errorf("zizmor: binary not found on PATH")
	}
	doc, err := z.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeZizmor(doc), nil
}

// execute runs the zizmor subprocess and captures its SARIF output from stdout.
// Exit code 1 means findings were found — not a crash.
func (z *Zizmor) execute(ctx context.Context, target string) (*zizmorSARIF, error) {
	cmd := z.execFunc(ctx, "zizmor", "--format", "sarif", target)
	// Output() captures stdout and returns it even when cmd exits non-zero,
	// so we can parse the SARIF regardless of whether findings were present.
	out, err := cmd.Output()
	if err != nil && !isZizmorFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("zizmor: %w", ctx.Err())
		}
		return nil, fmt.Errorf("zizmor: running scanner: %w", err)
	}
	return parseZizmorSARIF(out)
}

// parseZizmorSARIF unmarshals SARIF JSON from the bytes zizmor writes to stdout.
func parseZizmorSARIF(data []byte) (*zizmorSARIF, error) {
	if len(data) == 0 {
		return &zizmorSARIF{}, nil
	}
	var doc zizmorSARIF
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("zizmor: parsing SARIF: %w", err)
	}
	return &doc, nil
}

// normalizeZizmor converts a parsed zizmor SARIF document to the unified Finding schema.
func normalizeZizmor(doc *zizmorSARIF) []normalizer.Finding {
	if doc == nil || len(doc.Runs) == 0 {
		return nil
	}
	run := doc.Runs[0]
	ruleMap := zizmorRuleMap(run.Tool.Driver.Rules)
	out := make([]normalizer.Finding, 0, len(run.Results))
	for _, r := range run.Results {
		out = append(out, normalizeOneZizmor(r, ruleMap))
	}
	return out
}

// zizmorRuleMap indexes rules by their ID for O(1) metadata lookup.
func zizmorRuleMap(rules []zizmorRule) map[string]zizmorRule {
	m := make(map[string]zizmorRule, len(rules))
	for _, r := range rules {
		m[r.ID] = r
	}
	return m
}

// normalizeOneZizmor maps a single SARIF result to a Finding.
func normalizeOneZizmor(r zizmorResult, rules map[string]zizmorRule) normalizer.Finding {
	file, line, col := zizmorExtractLocation(r.Locations)
	fp := r.Fingerprints["primary"]
	if fp == "" {
		fp = zizmorFingerprint(file, line, r.RuleID)
	}
	// Prefer the helpUri from rule metadata; fall back to the canonical docs URL.
	ruleURL := "https://woodruffw.github.io/zizmor/audits/" + r.RuleID
	if rule, ok := rules[r.RuleID]; ok && rule.HelpURI != "" {
		ruleURL = rule.HelpURI
	}
	return normalizer.Finding{
		ID:          fp,
		Tool:        "zizmor",
		Severity:    zizmorSeverity(r.Level),
		Title:       r.Message.Text,
		Description: r.Message.Text,
		File:        file,
		Line:        line,
		Column:      col,
		RuleID:      r.RuleID,
		RuleURL:     ruleURL,
		Fingerprint: fp,
	}
}

// zizmorExtractLocation pulls the file path, line, and column from the first
// SARIF location entry. Returns zero values when no locations are present.
func zizmorExtractLocation(locs []zizmorLocation) (file string, line, col int) {
	if len(locs) == 0 {
		return "", 0, 0
	}
	pl := locs[0].PhysicalLocation
	return pl.ArtifactLocation.URI, pl.Region.StartLine, pl.Region.StartColumn
}

// zizmorSeverity maps a SARIF level string to a Muninn Severity.
// The mapping follows the SARIF severity taxonomy used by zizmor.
func zizmorSeverity(level string) normalizer.Severity {
	switch level {
	case "error":
		return normalizer.SeverityCritical
	case "warning":
		return normalizer.SeverityHigh
	case "note":
		return normalizer.SeverityMedium
	default:
		return normalizer.SeverityLow
	}
}

// zizmorFingerprint returns the first 16 hex chars of SHA-256(zizmor:file:line:ruleID).
// Used when the SARIF output does not include a fingerprint.
func zizmorFingerprint(file string, line int, ruleID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("zizmor:%s:%d:%s", file, line, ruleID)))
	return fmt.Sprintf("%x", sum[:8])
}

// isZizmorFindingsFound reports whether err is an exit-code-1 from zizmor,
// which means the scan completed and found issues — not a crash.
func isZizmorFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
