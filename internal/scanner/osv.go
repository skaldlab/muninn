package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// osvOutput mirrors the top-level JSON object osv-scanner writes to stdout.
type osvOutput struct {
	Results []osvResult `json:"results"`
}

// osvResult mirrors one entry in the results array (one lockfile source).
type osvResult struct {
	Source struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"source"`
	Packages []osvPackage `json:"packages"`
}

// osvPackage mirrors one package entry, containing its metadata and all
// vulnerabilities that affect it.
type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Vulnerabilities []osvVuln `json:"vulnerabilities"`
}

// osvVuln mirrors one vulnerability entry within a package.
// Only fields Muninn needs are mapped; unknown fields are silently ignored.
type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
	// Severity holds CVSS entries used as a fallback when DatabaseSpecific is absent.
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Aliases    []string `json:"aliases"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// OSVScanner wraps the Google OSV-Scanner for dependency CVE detection.
// See: https://github.com/google/osv-scanner
type OSVScanner struct {
	// execFunc creates the exec.Cmd for the osv-scanner subprocess.
	// Tests inject a fake that writes fixture JSON to stdout without
	// requiring a real binary on PATH.
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath resolves a binary name on PATH.
	// Tests inject a fake to control IsAvailable() without installing osv-scanner.
	lookPath func(string) (string, error)
}

// NewOSVScanner returns an OSVScanner ready for production use.
func NewOSVScanner() *OSVScanner {
	return &OSVScanner{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (o *OSVScanner) Name() string { return "osv-scanner" }

// IsAvailable implements Scanner.
func (o *OSVScanner) IsAvailable() bool {
	_, err := o.lookPath("osv-scanner")
	return err == nil
}

// Run implements Scanner.
func (o *OSVScanner) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !o.IsAvailable() {
		return nil, fmt.Errorf("osv-scanner: binary not found on PATH")
	}
	doc, err := o.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizeOSV(doc), nil
}

// execute runs the osv-scanner subprocess and captures its JSON output from stdout.
// Exit code 1 means vulnerabilities were found — not a crash.
func (o *OSVScanner) execute(ctx context.Context, target string) (*osvOutput, error) {
	cmd := o.execFunc(ctx, "osv-scanner", "--format", "json", "--recursive", target)
	out, err := cmd.Output()
	if err != nil && !isOSVFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("osv-scanner: %w", ctx.Err())
		}
		return nil, fmt.Errorf("osv-scanner: running scanner: %w", err)
	}
	return parseOSVJSON(out)
}

// parseOSVJSON unmarshals the JSON object osv-scanner writes to stdout.
func parseOSVJSON(data []byte) (*osvOutput, error) {
	if len(data) == 0 {
		return &osvOutput{}, nil
	}
	var doc osvOutput
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("osv-scanner: parsing JSON: %w", err)
	}
	return &doc, nil
}

// normalizeOSV flattens the nested results→packages→vulnerabilities structure
// into a flat []Finding — one Finding per (package, vulnerability) pair.
func normalizeOSV(doc *osvOutput) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	var out []normalizer.Finding
	for _, result := range doc.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				out = append(out, normalizeOneOSV(result.Source.Path, pkg, vuln))
			}
		}
	}
	return out
}

// normalizeOneOSV maps one (source path, package, vulnerability) triple to a Finding.
func normalizeOneOSV(sourcePath string, pkg osvPackage, vuln osvVuln) normalizer.Finding {
	fp := osvFingerprint(pkg.Package.Name, pkg.Package.Version, vuln.ID)
	return normalizer.Finding{
		ID:          fp,
		Tool:        "osv-scanner",
		Severity:    osvSeverity(vuln),
		Title:       vuln.Summary,
		Description: vuln.Details,
		File:        sourcePath,
		Line:        0,
		RuleID:      vuln.ID,
		RuleURL:     osvRuleURL(vuln),
		Fingerprint: fp,
		Metadata: map[string]any{
			"package":   pkg.Package.Name,
			"version":   pkg.Package.Version,
			"ecosystem": pkg.Package.Ecosystem,
			"aliases":   vuln.Aliases,
		},
	}
}

// osvSeverity maps a vulnerability to a Muninn Severity.
// It prefers database_specific.severity because advisory maintainers curate
// it; CVSS vector/score parsing is used only as a fallback.
func osvSeverity(vuln osvVuln) normalizer.Severity {
	switch strings.ToUpper(vuln.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return normalizer.SeverityCritical
	case "HIGH":
		return normalizer.SeverityHigh
	case "MODERATE", "MEDIUM":
		return normalizer.SeverityMedium
	case "LOW":
		return normalizer.SeverityLow
	}
	return osvSeverityFromCVSS(vuln)
}

// osvSeverityFromCVSS parses a numeric CVSS base score from the severity array
// and maps it to a Muninn Severity using standard CVSS v3 thresholds.
// Vector strings (e.g. "CVSS:3.1/AV:N/...") are not numeric and are skipped.
func osvSeverityFromCVSS(vuln osvVuln) normalizer.Severity {
	for _, s := range vuln.Severity {
		score, err := strconv.ParseFloat(s.Score, 64)
		if err != nil {
			continue
		}
		switch {
		case score >= 9.0:
			return normalizer.SeverityCritical
		case score >= 7.0:
			return normalizer.SeverityHigh
		case score >= 4.0:
			return normalizer.SeverityMedium
		default:
			return normalizer.SeverityLow
		}
	}
	return normalizer.SeverityInfo
}

// osvRuleURL returns the first reference URL whose type is "WEB" or "ADVISORY".
func osvRuleURL(vuln osvVuln) string {
	for _, ref := range vuln.References {
		t := strings.ToUpper(ref.Type)
		if t == "WEB" || t == "ADVISORY" {
			return ref.URL
		}
	}
	return ""
}

// osvFingerprint returns the first 16 hex chars of
// SHA-256(osv-scanner:name:version:vulnID).
func osvFingerprint(name, version, vulnID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("osv-scanner:%s:%s:%s", name, version, vulnID)))
	return fmt.Sprintf("%x", sum[:8])
}

// isOSVFindingsFound reports whether err is an exit-code-1 from osv-scanner,
// which means the scan completed and found vulnerabilities — not a crash.
func isOSVFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
