package normalizer

import "testing"

func TestAdvisoryID_PrefersCVEOverGHSA(t *testing.T) {
	f := Finding{
		RuleID:   "GHSA-jfh8-c2jp-5v3q",
		Metadata: map[string]any{"aliases": []string{"CVE-2021-23337"}},
	}
	if got := AdvisoryID(f); got != "CVE-2021-23337" {
		t.Errorf("AdvisoryID = %q, want CVE-2021-23337", got)
	}
}

func TestAdvisoryID_NormalizesCVECase(t *testing.T) {
	if got := AdvisoryID(Finding{RuleID: "cve-2021-23337"}); got != "CVE-2021-23337" {
		t.Errorf("AdvisoryID = %q, want upper-cased CVE", got)
	}
}

func TestAdvisoryID_FallsBackToGHSA(t *testing.T) {
	if got := AdvisoryID(Finding{RuleID: "GHSA-jfh8-c2jp-5v3q"}); got != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("AdvisoryID = %q, want GHSA fallback", got)
	}
}

func TestAdvisoryID_PrefersCVEFromAnyAliases(t *testing.T) {
	f := Finding{
		RuleID:   "GHSA-jfh8-c2jp-5v3q",
		Metadata: map[string]any{"aliases": []any{"CVE-2024-0001", 42}},
	}
	if got := AdvisoryID(f); got != "CVE-2024-0001" {
		t.Errorf("AdvisoryID = %q, want CVE-2024-0001 from []any aliases", got)
	}
}

func TestAdvisoryID_EcosystemSchemes(t *testing.T) {
	for _, id := range []string{"PYSEC-2021-1", "RUSTSEC-2020-0001", "GO-2022-0001", "OSV-2021-1"} {
		if got := AdvisoryID(Finding{RuleID: id}); got != id {
			t.Errorf("AdvisoryID(%q) = %q, want same", id, got)
		}
	}
}

func TestAdvisoryID_NonAdvisoryIsEmpty(t *testing.T) {
	for _, id := range []string{"generic-api-key", "CKV_AWS_18", "G404", ""} {
		if got := AdvisoryID(Finding{RuleID: id}); got != "" {
			t.Errorf("AdvisoryID(%q) = %q, want empty", id, got)
		}
	}
}
