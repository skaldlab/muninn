package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// semgrepOutput mirrors the top-level JSON object semgrep writes to stdout.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

// semgrepResult mirrors one entry in semgrep's results array.
// Only the fields Muninn needs are mapped; unknown fields are silently ignored.
type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	Extra struct {
		Message     string          `json:"message"`
		Severity    string          `json:"severity"`
		Fingerprint string          `json:"fingerprint"`
		Metadata    semgrepMetadata `json:"metadata"`
	} `json:"extra"`
}

// semgrepMetadata holds the fields inside extra.metadata that affect severity
// and rule URL construction.
type semgrepMetadata struct {
	Confidence string   `json:"confidence"`
	Impact     string   `json:"impact"`
	References []string `json:"references"`
}

// Semgrep wraps the semgrep SAST scanner.
// See: https://semgrep.dev
type Semgrep struct {
	// execFunc creates the exec.Cmd for the semgrep subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing semgrep.
	lookPath func(string) (string, error)

	rulesets     []string
	excludePaths []string
}

// NewSemgrep returns a Semgrep scanner ready for production use.
func NewSemgrep() *Semgrep {
	return &Semgrep{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (s *Semgrep) Name() string { return "semgrep" }

// IsAvailable implements Scanner.
func (s *Semgrep) IsAvailable() bool {
	_, err := s.lookPath("semgrep")
	return err == nil
}

// Configure implements Scanner. It applies rulesets and exclude_paths from
// muninn.yml. When no rulesets are configured the defaults are used at
// runtime.
func (s *Semgrep) Configure(cfg config.ScannerConfig) {
	s.rulesets = cfg.Rulesets
	s.excludePaths = cfg.ExcludePaths
}

// Run implements Scanner.
func (s *Semgrep) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep: binary not found on PATH")
	}
	doc, err := s.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeSemgrep(doc), nil
}

// execute runs the semgrep subprocess and captures its JSON output from stdout.
// Exit code 1 means findings were found — not a crash. Exit code 2 is fatal.
func (s *Semgrep) execute(ctx context.Context, target string) (*semgrepOutput, error) {
	args := s.buildArgs(target)
	cmd := s.execFunc(ctx, "semgrep", args...)
	// Output() captures stdout even when cmd exits non-zero.
	out, err := cmd.Output()
	if err != nil && !isSemgrepFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("semgrep: %w", ctx.Err())
		}
		return nil, fmt.Errorf("semgrep: running scanner: %w", err)
	}
	return parseSemgrepJSON(out)
}

// buildArgs constructs the semgrep CLI argument list from the configured
// rulesets and exclude paths. Falls back to the default rulesets when none
// have been configured via Configure.
func (s *Semgrep) buildArgs(target string) []string {
	rulesets := s.rulesets
	if len(rulesets) == 0 {
		rulesets = []string{"p/security-audit", "p/secrets"}
	}
	args := []string{"scan", "--json", "--no-rewrite-rule-ids"}
	for _, r := range rulesets {
		args = append(args, "--config", r)
	}
	for _, p := range s.excludePaths {
		args = append(args, "--exclude", p)
	}
	return append(args, target)
}

// parseSemgrepJSON unmarshals the JSON object semgrep writes to stdout.
func parseSemgrepJSON(data []byte) (*semgrepOutput, error) {
	if len(data) == 0 {
		return &semgrepOutput{}, nil
	}
	var doc semgrepOutput
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("semgrep: parsing JSON: %w", err)
	}
	return &doc, nil
}

// normalizeSemgrep converts a parsed semgrep document to the unified Finding schema.
func normalizeSemgrep(doc *semgrepOutput) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	out := make([]normalizer.Finding, 0, len(doc.Results))
	for _, r := range doc.Results {
		out = append(out, normalizeOneSemgrep(r))
	}
	return out
}

// normalizeOneSemgrep maps a single semgrep result to a Finding.
func normalizeOneSemgrep(r semgrepResult) normalizer.Finding {
	fp := r.Extra.Fingerprint
	if fp == "" {
		fp = semgrepFingerprint(r.Path, r.Start.Line, r.CheckID)
	}
	return normalizer.Finding{
		ID:          fp,
		Tool:        "semgrep",
		Severity:    semgrepSeverity(r.Extra.Severity, r.Extra.Metadata),
		Title:       semgrepTitle(r.CheckID),
		Description: r.Extra.Message,
		File:        r.Path,
		Line:        r.Start.Line,
		Column:      r.Start.Col,
		RuleID:      r.CheckID,
		RuleURL:     semgrepRuleURL(r.CheckID, r.Extra.Metadata.References),
		Fingerprint: fp,
	}
}

// semgrepSeverity maps a semgrep severity string to a Muninn Severity.
// Findings with ERROR severity are upgraded to critical when both impact
// and confidence are HIGH, reflecting higher-signal rules.
func semgrepSeverity(severity string, meta semgrepMetadata) normalizer.Severity {
	up := strings.ToUpper
	if up(severity) == "ERROR" && up(meta.Impact) == "HIGH" && up(meta.Confidence) == "HIGH" {
		return normalizer.SeverityCritical
	}
	switch up(severity) {
	case "ERROR":
		return normalizer.SeverityHigh
	case "WARNING":
		return normalizer.SeverityMedium
	default:
		return normalizer.SeverityLow
	}
}

// semgrepTitle derives a human-readable title from check_id by taking the last
// dot-separated segment and replacing hyphens/underscores with spaces.
func semgrepTitle(checkID string) string {
	parts := strings.Split(checkID, ".")
	last := parts[len(parts)-1]
	return strings.NewReplacer("-", " ", "_", " ").Replace(last)
}

// semgrepRuleURL returns the first reference URL if the rule metadata provides
// one, otherwise falls back to the canonical semgrep registry URL.
func semgrepRuleURL(checkID string, refs []string) string {
	if len(refs) > 0 {
		return refs[0]
	}
	return "https://semgrep.dev/r/" + checkID
}

// semgrepFingerprint returns the first 16 hex chars of SHA-256(semgrep:path:line:checkID).
// Used when semgrep does not supply a fingerprint for the result.
func semgrepFingerprint(path string, line int, checkID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("semgrep:%s:%d:%s", path, line, checkID)))
	return fmt.Sprintf("%x", sum[:8])
}

// isSemgrepFindingsFound reports whether err is an exit-code-1 from semgrep,
// which means the scan completed and found issues — not a crash.
func isSemgrepFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
