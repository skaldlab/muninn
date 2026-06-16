//go:build integration

package integration_test

import (
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// TestFullScan_CrossScannerDedup verifies the issue #27 behavior end-to-end with
// real scanners: the lodash advisory in the fixture's package-lock.json is
// reported by both osv-scanner (as a GHSA with the CVE in aliases) and trivy (as
// the CVE), and must collapse into a single finding whose detected_by records
// both scanners.
func TestFullScan_CrossScannerDedup(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(t), "--output", "json")...)
	report := readJSONReport(t, res)

	merged := crossScannerFindings(report.Findings)
	if len(merged) == 0 {
		t.Fatalf("expected at least one finding detected by multiple scanners, got none among %d findings", len(report.Findings))
	}

	var sawOSVTrivy bool
	for _, f := range merged {
		if hasDuplicateScanner(f.DetectedBy) {
			t.Errorf("detected_by lists a scanner more than once: %v (rule %s)", f.DetectedBy, f.RuleID)
		}
		if containsScanners(f.DetectedBy, "osv-scanner", "trivy") {
			sawOSVTrivy = true
		}
	}
	if !sawOSVTrivy {
		t.Errorf("expected a finding detected by both osv-scanner and trivy; merged findings: %+v", merged)
	}
}

// crossScannerFindings returns the findings attributed to more than one scanner.
func crossScannerFindings(findings []normalizer.Finding) []normalizer.Finding {
	var out []normalizer.Finding
	for _, f := range findings {
		if len(f.DetectedBy) > 1 {
			out = append(out, f)
		}
	}
	return out
}

// containsScanners reports whether detectedBy contains every wanted scanner.
func containsScanners(detectedBy []string, wants ...string) bool {
	for _, w := range wants {
		found := false
		for _, d := range detectedBy {
			if d == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// hasDuplicateScanner reports whether detectedBy names any scanner twice.
func hasDuplicateScanner(detectedBy []string) bool {
	seen := make(map[string]bool, len(detectedBy))
	for _, d := range detectedBy {
		if seen[d] {
			return true
		}
		seen[d] = true
	}
	return false
}
