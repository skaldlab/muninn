package main

import (
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// TestDedupeByAdvisory_MergesCrossScanner is the core of issue #27: osv-scanner
// reports the advisory under its GHSA id (CVE in aliases) from a lockfile while
// trivy reports the same CVE for the same package from a container layer. They
// must collapse into one finding that records both scanners.
func TestDedupeByAdvisory_MergesCrossScanner(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "osv-scanner", Severity: normalizer.SeverityHigh, RuleID: "GHSA-jfh8-c2jp-5v3q",
			File: "package-lock.json", Metadata: map[string]any{"package": "lodash", "aliases": []string{"CVE-2021-23337"}}},
		{Tool: "trivy", Severity: normalizer.SeverityHigh, RuleID: "CVE-2021-23337",
			File: "Dockerfile", Metadata: map[string]any{"pkg_name": "lodash"}},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].Tool != "osv-scanner" {
		t.Errorf("primary tool = %q, want osv-scanner (first in pipeline order)", out[0].Tool)
	}
	if out[0].File != "package-lock.json" {
		t.Errorf("primary file = %q, want package-lock.json (canonical location)", out[0].File)
	}
	want := []string{"osv-scanner", "trivy"}
	if len(out[0].DetectedBy) != 2 || out[0].DetectedBy[0] != want[0] || out[0].DetectedBy[1] != want[1] {
		t.Errorf("DetectedBy = %v, want %v", out[0].DetectedBy, want)
	}
}

func TestDedupeByAdvisory_DifferentPackagesNotMerged(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "trivy", RuleID: "CVE-2021-0001", Metadata: map[string]any{"pkg_name": "libfoo"}},
		{Tool: "trivy", RuleID: "CVE-2021-0001", Metadata: map[string]any{"pkg_name": "libbar"}},
	}
	if out := dedupeByAdvisory(in); len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2 (same CVE, different packages stay separate)", len(out))
	}
}

func TestDedupeByAdvisory_NonAdvisoryNeverMerged(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "gitleaks", RuleID: "generic-api-key", File: "a.yml"},
		{Tool: "gitleaks", RuleID: "generic-api-key", File: "b.yml"},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2 (secrets never merge)", len(out))
	}
	if out[0].DetectedBy != nil {
		t.Errorf("DetectedBy = %v, want nil for unmerged finding", out[0].DetectedBy)
	}
}

func TestDedupeByAdvisory_ActiveWhenAnyVariantUnsuppressed(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "osv-scanner", RuleID: "CVE-2021-0009", Metadata: map[string]any{"package": "p"}, Suppressed: true},
		{Tool: "trivy", RuleID: "CVE-2021-0009", Metadata: map[string]any{"pkg_name": "p"}, Suppressed: false},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].Suppressed {
		t.Error("merged finding should be active when any variant is unsuppressed")
	}
}

func TestDedupeByAdvisory_SuppressedWhenAllVariantsSuppressed(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "osv-scanner", RuleID: "CVE-2021-0009", Metadata: map[string]any{"package": "p"}, Suppressed: true},
		{Tool: "trivy", RuleID: "CVE-2021-0009", Metadata: map[string]any{"pkg_name": "p"}, Suppressed: true},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 1 || !out[0].Suppressed {
		t.Errorf("want one suppressed finding; got len=%d suppressed=%v", len(out), out[0].Suppressed)
	}
}

func TestDedupeByAdvisory_SameToolNotListedTwice(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "osv-scanner", RuleID: "CVE-2021-0002", Metadata: map[string]any{"package": "p"}},
		{Tool: "osv-scanner", RuleID: "CVE-2021-0002", Metadata: map[string]any{"package": "p"}},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].DetectedBy != nil {
		t.Errorf("DetectedBy = %v, want nil for single-scanner finding", out[0].DetectedBy)
	}
}

func TestDedupeByAdvisory_PreservesOrder(t *testing.T) {
	in := []normalizer.Finding{
		{Tool: "gitleaks", RuleID: "generic-api-key", File: "a.yml"},
		{Tool: "osv-scanner", RuleID: "CVE-2021-0003", Metadata: map[string]any{"package": "p"}},
		{Tool: "trivy", RuleID: "CVE-2021-0003", Metadata: map[string]any{"pkg_name": "p"}},
		{Tool: "semgrep", RuleID: "some.sast.rule", File: "b.go"},
	}
	out := dedupeByAdvisory(in)
	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3", len(out))
	}
	gotRules := []string{out[0].RuleID, out[1].RuleID, out[2].RuleID}
	want := []string{"generic-api-key", "CVE-2021-0003", "some.sast.rule"}
	for i := range want {
		if gotRules[i] != want[i] {
			t.Errorf("out[%d].RuleID = %q, want %q", i, gotRules[i], want[i])
		}
	}
}
