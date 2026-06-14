package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// poutineOutput mirrors the top-level JSON object poutine writes to stdout.
type poutineOutput struct {
	Findings []poutineFinding `json:"findings"`
}

// poutineFinding mirrors one entry in poutine's findings array.
// Only the fields Muninn needs are mapped; unknown fields are silently ignored.
type poutineFinding struct {
	Rule struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	} `json:"rule"`
	Occurrence struct {
		File        string `json:"file"`
		StartLine   int    `json:"startLine"`
		StartColumn int    `json:"startColumn"`
	} `json:"occurrence"`
	Fingerprint string `json:"fingerprint"`
}

// Poutine wraps the poutine supply-chain pipeline risk scanner.
// See: https://github.com/boostsecurityio/poutine
type Poutine struct {
	// execFunc creates the exec.Cmd for the poutine subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing poutine.
	lookPath func(string) (string, error)
}

// NewPoutine returns a Poutine scanner ready for production use.
func NewPoutine() *Poutine {
	return &Poutine{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (p *Poutine) Name() string { return "poutine" }

// IsAvailable implements Scanner.
func (p *Poutine) IsAvailable() bool {
	_, err := p.lookPath("poutine")
	return err == nil
}

// Configure implements Scanner. Poutine has no configurable options.
func (p *Poutine) Configure(_ config.ScannerConfig) {}

// Run implements Scanner.
func (p *Poutine) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !p.IsAvailable() {
		return nil, fmt.Errorf("poutine: binary not found on PATH")
	}
	// Skip gracefully when the target directory does not exist rather than
	// letting poutine fail with an opaque error.
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return nil, nil
	}
	doc, err := p.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizePoutine(doc), nil
}

// execute runs the poutine subprocess and captures its JSON output from stdout.
// Poutine exits 0 for both the no-findings and findings-present cases; any
// non-zero exit indicates a real error.
func (p *Poutine) execute(ctx context.Context, target string) (*poutineOutput, error) {
	cmd := p.execFunc(ctx, "poutine", "analyze_local", target, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("poutine: %w", ctx.Err())
		}
		return nil, fmt.Errorf("poutine: running scanner: %w", err)
	}
	return parsePoutineJSON(out)
}

// parsePoutineJSON unmarshals the JSON object poutine writes to stdout.
func parsePoutineJSON(data []byte) (*poutineOutput, error) {
	if len(data) == 0 {
		return &poutineOutput{}, nil
	}
	var doc poutineOutput
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("poutine: parsing JSON: %w", err)
	}
	return &doc, nil
}

// normalizePoutine converts a parsed poutine document to the unified Finding schema.
func normalizePoutine(doc *poutineOutput) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	out := make([]normalizer.Finding, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		out = append(out, normalizeOnePoutine(f))
	}
	return out
}

// normalizeOnePoutine maps a single poutine finding to a Finding.
func normalizeOnePoutine(f poutineFinding) normalizer.Finding {
	fp := f.Fingerprint
	if fp == "" {
		fp = poutineFingerprint(f.Occurrence.File, f.Occurrence.StartLine, f.Rule.ID)
	}
	return normalizer.Finding{
		ID:          fp,
		Tool:        "poutine",
		Severity:    poutineSeverity(f.Rule.Severity),
		Title:       f.Rule.Title,
		Description: f.Rule.Description,
		File:        f.Occurrence.File,
		Line:        f.Occurrence.StartLine,
		Column:      f.Occurrence.StartColumn,
		RuleID:      f.Rule.ID,
		RuleURL:     "https://github.com/boostsecurityio/poutine/blob/main/docs/rules/" + f.Rule.ID + ".md",
		Fingerprint: fp,
	}
}

// poutineSeverity maps a poutine severity string directly to a Muninn Severity.
// Poutine uses the same vocabulary as Muninn for the four main levels.
func poutineSeverity(severity string) normalizer.Severity {
	switch severity {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium":
		return normalizer.SeverityMedium
	case "low":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}

// poutineFingerprint returns the first 16 hex chars of SHA-256(poutine:file:line:ruleID).
// Used when poutine does not supply a fingerprint for the finding.
func poutineFingerprint(file string, line int, ruleID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("poutine:%s:%d:%s", file, line, ruleID)))
	return fmt.Sprintf("%x", sum[:8])
}
