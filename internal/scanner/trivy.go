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

// trivyOutput mirrors the top-level JSON object trivy writes to stdout.
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

// trivyResult mirrors one entry in the Results array (one scanned target).
type trivyResult struct {
	Target          string      `json:"Target"`
	Class           string      `json:"Class"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

// trivyVuln mirrors one vulnerability entry within a result.
// Only fields Muninn needs are mapped; unknown fields are silently ignored.
type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
}

// Trivy wraps the Aqua Security Trivy container and filesystem scanner.
// See: https://github.com/aquasecurity/trivy
type Trivy struct {
	// execFunc creates the exec.Cmd for the trivy subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing trivy.
	lookPath func(string) (string, error)

	severity      []string
	ignoreUnfixed bool
}

// NewTrivy returns a Trivy scanner ready for production use.
func NewTrivy() *Trivy {
	return &Trivy{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (t *Trivy) Name() string { return "trivy" }

// IsAvailable implements Scanner.
func (t *Trivy) IsAvailable() bool {
	_, err := t.lookPath("trivy")
	return err == nil
}

// Configure implements Scanner. It applies severity filter and ignore-unfixed
// flag from muninn.yml.
func (t *Trivy) Configure(cfg config.ScannerConfig) {
	t.severity = cfg.Severity
	t.ignoreUnfixed = cfg.IgnoreUnfixed
}

// Run implements Scanner.
func (t *Trivy) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !t.IsAvailable() {
		return nil, fmt.Errorf("trivy: binary not found on PATH")
	}
	doc, err := t.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeTrivy(doc), nil
}

// execute runs the trivy subprocess and captures its JSON output from stdout.
// Exit code 1 means findings were found — not a crash.
func (t *Trivy) execute(ctx context.Context, target string) (*trivyOutput, error) {
	cmd := t.execFunc(ctx, "trivy", t.buildArgs(target)...)
	out, err := cmd.Output()
	if err != nil && !isTrivyFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("trivy: %w", ctx.Err())
		}
		return nil, fmt.Errorf("trivy: running scanner: %w", err)
	}
	return parseTrivyJSON(out)
}

// buildArgs constructs the trivy CLI argument list from the configured
// severity filter and ignore-unfixed flag. Falls back to
// config.DefaultTrivySeverities when no severity is configured via Configure.
func (t *Trivy) buildArgs(target string) []string {
	sev := strings.Join(t.severity, ",")
	if sev == "" {
		sev = strings.Join(config.DefaultTrivySeverities, ",")
	}
	args := []string{"fs", "--format", "json", "--quiet", "--severity", sev}
	if t.ignoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	return append(args, target)
}

// parseTrivyJSON unmarshals the JSON object trivy writes to stdout.
func parseTrivyJSON(data []byte) (*trivyOutput, error) {
	if len(data) == 0 {
		return &trivyOutput{}, nil
	}
	var doc trivyOutput
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("trivy: parsing JSON: %w", err)
	}
	return &doc, nil
}

// normalizeTrivy flattens the Results → Vulnerabilities structure into a flat
// []Finding — one Finding per (result target, vulnerability) pair.
func normalizeTrivy(doc *trivyOutput) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	var out []normalizer.Finding
	for _, result := range doc.Results {
		for _, vuln := range result.Vulnerabilities {
			out = append(out, normalizeOneTrivy(result.Target, vuln))
		}
	}
	return out
}

// normalizeOneTrivy maps one (target, vulnerability) pair to a Finding.
func normalizeOneTrivy(target string, vuln trivyVuln) normalizer.Finding {
	fp := trivyFingerprint(target, vuln.VulnerabilityID, vuln.PkgName)
	return normalizer.Finding{
		ID:          fp,
		Tool:        "trivy",
		Severity:    trivySeverity(vuln.Severity),
		Title:       vuln.Title,
		Description: vuln.Description,
		File:        target,
		Line:        0,
		RuleID:      vuln.VulnerabilityID,
		RuleURL:     vuln.PrimaryURL,
		Fingerprint: fp,
		Metadata: map[string]any{
			"pkg_name":          vuln.PkgName,
			"installed_version": vuln.InstalledVersion,
			"fixed_version":     vuln.FixedVersion,
			"cwe_ids":           vuln.CweIDs,
		},
	}
}

// trivySeverity maps a trivy severity string to a Muninn Severity.
func trivySeverity(severity string) normalizer.Severity {
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

// trivyFingerprint returns the first 16 hex chars of
// SHA-256(trivy:target:vulnID:pkgName).
func trivyFingerprint(target, vulnID, pkgName string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("trivy:%s:%s:%s", target, vulnID, pkgName)))
	return fmt.Sprintf("%x", sum[:8])
}

// isTrivyFindingsFound reports whether err is an exit-code-1 from trivy,
// which means the scan completed and found vulnerabilities — not a crash.
func isTrivyFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
