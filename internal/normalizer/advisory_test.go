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

func TestPackageAccessors(t *testing.T) {
	osv := Finding{Metadata: map[string]any{"package": "lodash", "version": "4.17.20", "ecosystem": "npm"}}
	if got := PackageName(osv); got != "lodash" {
		t.Errorf("PackageName(osv) = %q, want lodash", got)
	}
	if got := PackageVersion(osv); got != "4.17.20" {
		t.Errorf("PackageVersion(osv) = %q, want 4.17.20", got)
	}
	if got := Ecosystem(osv); got != "npm" {
		t.Errorf("Ecosystem(osv) = %q, want npm", got)
	}

	trivy := Finding{Metadata: map[string]any{"pkg_name": "openssl", "installed_version": "1.1.1"}}
	if got := PackageName(trivy); got != "openssl" {
		t.Errorf("PackageName(trivy) = %q, want openssl", got)
	}
	if got := PackageVersion(trivy); got != "1.1.1" {
		t.Errorf("PackageVersion(trivy) = %q, want 1.1.1", got)
	}

	if got := PackageName(Finding{}); got != "" {
		t.Errorf("PackageName(empty) = %q, want empty", got)
	}
}

func TestInjectionSources(t *testing.T) {
	f := Finding{Metadata: map[string]any{
		"injection_sources": []any{"github.event.pull_request.title"},
	}}
	got := InjectionSources(f)
	if len(got) != 1 || got[0] != "github.event.pull_request.title" {
		t.Errorf("InjectionSources() = %v, want one title source", got)
	}
	if got := InjectionSources(Finding{}); got != nil {
		t.Errorf("InjectionSources(empty) = %v, want nil", got)
	}
}
