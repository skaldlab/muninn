package reporter

import (
	"bytes"
	"context"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// SARIF.Write is currently a stub that returns nil regardless of input.
// These tests document expected stub behavior and will need updating when
// the full SARIF implementation lands.

func TestSARIFReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestSARIFReporter_WithFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Tool: "zizmor", Severity: normalizer.SeverityCritical, Fingerprint: "f1"},
		{ID: "f2", Tool: "trivy", Severity: normalizer.SeverityHigh, Fingerprint: "f2"},
	}
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	// Verify Write does not panic for any severity value.
	for _, sev := range []normalizer.Severity{
		normalizer.SeverityCritical,
		normalizer.SeverityHigh,
		normalizer.SeverityMedium,
		normalizer.SeverityLow,
		normalizer.SeverityInfo,
	} {
		f := normalizer.Finding{ID: string(sev), Severity: sev, Fingerprint: string(sev)}
		var buf bytes.Buffer
		r := &SARIF{}
		if err := r.Write(context.Background(), &buf, []normalizer.Finding{f}); err != nil {
			t.Errorf("Write(%s) unexpected error: %v", sev, err)
		}
	}
}

func TestSARIFReporter_UniqueRules(t *testing.T) {
	// Duplicate rule IDs should not panic the reporter.
	findings := []normalizer.Finding{
		{ID: "a", RuleID: "rule-1", Fingerprint: "a"},
		{ID: "b", RuleID: "rule-1", Fingerprint: "b"}, // same RuleID
	}
	var buf bytes.Buffer
	r := &SARIF{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestSARIFReporter_WriterError(t *testing.T) {
	// The stub ignores the writer, so this currently returns nil.
	// Once the real implementation lands, this should return a wrapped error.
	r := &SARIF{}
	_ = r.Write(context.Background(), errWriter{}, []normalizer.Finding{})
}
