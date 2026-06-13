package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// actionlintOutput mirrors one entry from actionlint's JSON report.
// Only the fields Muninn needs are mapped; other fields are silently ignored.
type actionlintOutput struct {
	Message  string `json:"message"`
	Filepath string `json:"filepath"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Severity string `json:"severity"`
	Rule     struct {
		Name string `json:"name"`
	} `json:"rule"`
}

// Actionlint wraps the actionlint GitHub Actions workflow linter.
// See: https://github.com/rhysd/actionlint
type Actionlint struct {
	// execFunc creates the exec.Cmd for the actionlint subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing actionlint.
	lookPath func(string) (string, error)
}

// NewActionlint returns an Actionlint scanner ready for production use.
func NewActionlint() *Actionlint {
	return &Actionlint{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (a *Actionlint) Name() string { return "actionlint" }

// IsAvailable implements Scanner.
func (a *Actionlint) IsAvailable() bool {
	_, err := a.lookPath("actionlint")
	return err == nil
}

// Run implements Scanner.
func (a *Actionlint) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !a.IsAvailable() {
		return nil, fmt.Errorf("actionlint: binary not found on PATH")
	}
	workflowsDir := filepath.Join(target, ".github", "workflows")
	// Repos without a .github/workflows directory have no workflows to scan;
	// this is not an error, just a no-op.
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return nil, nil
	}
	raw, err := a.execute(ctx, workflowsDir)
	if err != nil {
		return nil, err
	}
	return normalizeActionlint(raw), nil
}

// execute runs the actionlint subprocess and captures its JSON output from stdout.
// Exit code 1 means findings were found — not a crash.
func (a *Actionlint) execute(ctx context.Context, workflowsDir string) ([]actionlintOutput, error) {
	cmd := a.execFunc(ctx, "actionlint", "-format", "{{json .}}", workflowsDir)
	// Output() captures stdout and returns it even when cmd exits non-zero,
	// so we can parse the JSON regardless of whether findings were present.
	out, err := cmd.Output()
	if err != nil && !isActionlintFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("actionlint: %w", ctx.Err())
		}
		return nil, fmt.Errorf("actionlint: running scanner: %w", err)
	}
	return parseActionlintJSON(out)
}

// parseActionlintJSON unmarshals the JSON array actionlint writes to stdout.
func parseActionlintJSON(data []byte) ([]actionlintOutput, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out []actionlintOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("actionlint: parsing JSON: %w", err)
	}
	return out, nil
}

// normalizeActionlint converts raw actionlint output to the unified Finding schema.
func normalizeActionlint(raw []actionlintOutput) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(raw))
	for _, r := range raw {
		out = append(out, normalizeOneActionlint(r))
	}
	return out
}

// normalizeOneActionlint maps a single actionlint entry to a Finding.
func normalizeOneActionlint(r actionlintOutput) normalizer.Finding {
	fp := actionlintFingerprint(r.Filepath, r.Line, r.Rule.Name)
	return normalizer.Finding{
		ID:          fp,
		Tool:        "actionlint",
		Severity:    actionlintSeverity(r.Severity),
		Title:       r.Message,
		Description: r.Message,
		File:        r.Filepath,
		Line:        r.Line,
		Column:      r.Column,
		RuleID:      r.Rule.Name,
		RuleURL:     "https://rhysd.github.io/actionlint/",
		Fingerprint: fp,
	}
}

// actionlintSeverity maps an actionlint severity string to a Muninn Severity.
func actionlintSeverity(severity string) normalizer.Severity {
	switch severity {
	case "error":
		return normalizer.SeverityCritical
	case "warning":
		return normalizer.SeverityHigh
	case "info":
		return normalizer.SeverityMedium
	default:
		return normalizer.SeverityLow
	}
}

// actionlintFingerprint returns the first 16 hex chars of SHA-256(actionlint:file:line:rule).
// Actionlint does not supply fingerprints, so Muninn always generates one.
func actionlintFingerprint(file string, line int, ruleName string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("actionlint:%s:%d:%s", file, line, ruleName)))
	return fmt.Sprintf("%x", sum[:8])
}

// isActionlintFindingsFound reports whether err is an exit-code-1 from actionlint,
// which means the scan completed and found issues — not a crash.
func isActionlintFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
