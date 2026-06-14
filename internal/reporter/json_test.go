package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// errWriter is an io.Writer that always returns an error, used to test
// that reporters propagate writer failures to the caller.
type errWriter struct{}

func (e errWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write error")
}

// reportOut is a helper for deserializing the JSON reporter's wrapped output.
type reportOut struct {
	Version  string               `json:"version"`
	Tool     string               `json:"tool"`
	Summary  map[string]int       `json:"summary"`
	Findings []normalizer.Finding `json:"findings"`
}

func parseReportOut(t *testing.T, data []byte) reportOut {
	t.Helper()
	var out reportOut
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, data)
	}
	return out
}

func TestJSONReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := parseReportOut(t, buf.Bytes())
	if out.Version != "0.1.0" {
		t.Errorf("version = %q, want 0.1.0", out.Version)
	}
	if out.Tool != "muninn" {
		t.Errorf("tool = %q, want muninn", out.Tool)
	}
	if out.Summary["total"] != 0 {
		t.Errorf("summary.total = %d, want 0", out.Summary["total"])
	}
	if len(out.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(out.Findings))
	}
}

func TestJSONReporter_SingleFinding(t *testing.T) {
	f := normalizer.Finding{
		ID:          "fp1",
		Tool:        "gitleaks",
		Severity:    normalizer.SeverityHigh,
		Title:       "Secret found",
		Description: "Exposed token",
		File:        "main.go",
		Line:        10,
		RuleID:      "generic-api-key",
		Fingerprint: "fp1",
	}

	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{f}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	out := parseReportOut(t, buf.Bytes())
	if len(out.Findings) != 1 {
		t.Fatalf("len = %d, want 1", len(out.Findings))
	}
	if out.Findings[0].Tool != "gitleaks" {
		t.Errorf("Tool = %q, want gitleaks", out.Findings[0].Tool)
	}
	if out.Findings[0].Severity != normalizer.SeverityHigh {
		t.Errorf("Severity = %q, want high", out.Findings[0].Severity)
	}
	if out.Summary["high"] != 1 {
		t.Errorf("summary.high = %d, want 1", out.Summary["high"])
	}
}

func TestJSONReporter_MultipleFindings(t *testing.T) {
	// Findings are already in severity order (critical → high → medium).
	// The reporter sorts by severity, so order is preserved.
	findings := []normalizer.Finding{
		{ID: "a", Tool: "t1", Severity: normalizer.SeverityCritical, Fingerprint: "a"},
		{ID: "b", Tool: "t2", Severity: normalizer.SeverityHigh, Fingerprint: "b"},
		{ID: "c", Tool: "t3", Severity: normalizer.SeverityMedium, Fingerprint: "c"},
	}

	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	out := parseReportOut(t, buf.Bytes())
	if len(out.Findings) != 3 {
		t.Fatalf("len = %d, want 3", len(out.Findings))
	}
	// Severity order must be maintained.
	for i, want := range []string{"a", "b", "c"} {
		if out.Findings[i].ID != want {
			t.Errorf("findings[%d].ID = %q, want %q", i, out.Findings[i].ID, want)
		}
	}
	if out.Summary["total"] != 3 {
		t.Errorf("summary.total = %d, want 3", out.Summary["total"])
	}
}

func TestJSONReporter_AllSeverities(t *testing.T) {
	sevs := []normalizer.Severity{
		normalizer.SeverityCritical,
		normalizer.SeverityHigh,
		normalizer.SeverityMedium,
		normalizer.SeverityLow,
		normalizer.SeverityInfo,
	}
	findings := make([]normalizer.Finding, len(sevs))
	for i, s := range sevs {
		findings[i] = normalizer.Finding{ID: string(s), Severity: s, Fingerprint: string(s)}
	}

	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	out := parseReportOut(t, buf.Bytes())
	for i, want := range sevs {
		if out.Findings[i].Severity != want {
			t.Errorf("findings[%d].Severity = %q, want %q", i, out.Findings[i].Severity, want)
		}
	}
	if out.Summary["total"] != 5 {
		t.Errorf("summary.total = %d, want 5", out.Summary["total"])
	}
}

func TestJSONReporter_SummaryAccurate(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "1", Severity: normalizer.SeverityCritical, Fingerprint: "1"},
		{ID: "2", Severity: normalizer.SeverityCritical, Fingerprint: "2"},
		{ID: "3", Severity: normalizer.SeverityHigh, Fingerprint: "3"},
		{ID: "4", Severity: normalizer.SeverityInfo, Fingerprint: "4"},
	}
	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := parseReportOut(t, buf.Bytes())
	if out.Summary["total"] != 4 {
		t.Errorf("summary.total = %d, want 4", out.Summary["total"])
	}
	if out.Summary["critical"] != 2 {
		t.Errorf("summary.critical = %d, want 2", out.Summary["critical"])
	}
	if out.Summary["high"] != 1 {
		t.Errorf("summary.high = %d, want 1", out.Summary["high"])
	}
	if out.Summary["info"] != 1 {
		t.Errorf("summary.info = %d, want 1", out.Summary["info"])
	}
}

func TestJSONReporter_WriterError(t *testing.T) {
	r := &JSON{}
	err := r.Write(context.Background(), errWriter{}, []normalizer.Finding{
		{ID: "x", Fingerprint: "x"},
	})
	if err == nil {
		t.Fatal("Write() expected an error when writer fails, got nil")
	}
}
