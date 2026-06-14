package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// sarifOut is a minimal subset of the SARIF 2.1.0 schema used to verify
// reporter output in tests without importing a full SARIF library.
type sarifOut struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID string `json:"ruleId"`
			Level  string `json:"level"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, data []byte) sarifOut {
	t.Helper()
	var out sarifOut
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	return out
}

func TestSARIFReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	doc := parseSARIF(t, buf.Bytes())
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) == 0 {
		t.Fatal("SARIF must contain at least one run")
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0 for empty findings", len(doc.Runs[0].Results))
	}
}

func TestSARIFReporter_OmitsSuppressedFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", RuleID: "active-rule", Fingerprint: "a", Suppressed: false},
		{ID: "b", RuleID: "suppressed-rule", Fingerprint: "b", Suppressed: true},
	}
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	doc := parseSARIF(t, buf.Bytes())
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1 (suppressed finding omitted)", len(doc.Runs[0].Results))
	}
	if doc.Runs[0].Results[0].RuleID != "active-rule" {
		t.Errorf("results[0].ruleId = %q, want active-rule", doc.Runs[0].Results[0].RuleID)
	}
}

func TestSARIFReporter_WithFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Tool: "zizmor", RuleID: "z-rule", Severity: normalizer.SeverityCritical, Fingerprint: "f1"},
		{ID: "f2", Tool: "trivy", RuleID: "t-rule", Severity: normalizer.SeverityHigh, Fingerprint: "f2"},
	}
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	doc := parseSARIF(t, buf.Bytes())
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("results = %d, want 2", len(doc.Runs[0].Results))
	}
	if doc.Runs[0].Results[0].RuleID != "z-rule" {
		t.Errorf("results[0].ruleId = %q, want z-rule", doc.Runs[0].Results[0].RuleID)
	}
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	cases := []struct {
		sev   normalizer.Severity
		level string
	}{
		{normalizer.SeverityCritical, "error"},
		{normalizer.SeverityHigh, "error"},
		{normalizer.SeverityMedium, "warning"},
		{normalizer.SeverityLow, "note"},
		{normalizer.SeverityInfo, "none"},
	}
	for _, tc := range cases {
		f := normalizer.Finding{ID: string(tc.sev), Severity: tc.sev, Fingerprint: string(tc.sev)}
		var buf bytes.Buffer
		r := &SARIF{}
		if err := r.Write(context.Background(), &buf, []normalizer.Finding{f}); err != nil {
			t.Errorf("Write(%s) unexpected error: %v", tc.sev, err)
			continue
		}
		doc := parseSARIF(t, buf.Bytes())
		if doc.Runs[0].Results[0].Level != tc.level {
			t.Errorf("severity %s → level %q, want %q",
				tc.sev, doc.Runs[0].Results[0].Level, tc.level)
		}
	}
}

func TestSARIFReporter_UniqueRules(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", RuleID: "rule-1", Fingerprint: "a"},
		{ID: "b", RuleID: "rule-1", Fingerprint: "b"}, // same RuleID — must not duplicate
	}
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	doc := parseSARIF(t, buf.Bytes())
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 for duplicate RuleID", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if doc.Runs[0].Tool.Driver.Rules[0].ID != "rule-1" {
		t.Errorf("rule[0].id = %q, want rule-1", doc.Runs[0].Tool.Driver.Rules[0].ID)
	}
}

func TestSARIFReporter_WriterError(t *testing.T) {
	r := &SARIF{}
	if err := r.Write(context.Background(), errWriter{}, []normalizer.Finding{}); err == nil {
		t.Fatal("Write() with failing writer expected error, got nil")
	}
}

func TestToPascalCase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"aws-access-key", "AwsAccessKey"},
		{"CKV_AWS_18", "CkvAws18"},
		{"single", "Single"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := toPascalCase(tc.in); got != tc.want {
			t.Errorf("toPascalCase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
