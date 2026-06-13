package reporter

import (
	"bytes"
	"context"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Comment.Write is currently a stub that returns nil regardless of input.
// These tests document expected stub behavior and will need updating when
// the full Markdown implementation lands.

func TestCommentReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestCommentReporter_WithFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Tool: "gitleaks", Severity: normalizer.SeverityCritical,
			Title: "Exposed secret", File: "main.go", Line: 5, Fingerprint: "a"},
		{ID: "b", Tool: "semgrep", Severity: normalizer.SeverityHigh,
			Title: "SQL injection", File: "db.go", Line: 20, Fingerprint: "b"},
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestCommentReporter_GroupsBySeverity(t *testing.T) {
	// Verify Write does not panic when findings span all severity levels.
	findings := []normalizer.Finding{
		{ID: "1", Severity: normalizer.SeverityLow, Fingerprint: "1"},
		{ID: "2", Severity: normalizer.SeverityCritical, Fingerprint: "2"},
		{ID: "3", Severity: normalizer.SeverityMedium, Fingerprint: "3"},
		{ID: "4", Severity: normalizer.SeverityHigh, Fingerprint: "4"},
		{ID: "5", Severity: normalizer.SeverityInfo, Fingerprint: "5"},
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestCommentReporter_TruncatesLongDescription(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	f := normalizer.Finding{
		ID: "z", Severity: normalizer.SeverityMedium,
		Description: string(long), Fingerprint: "z",
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{f}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
}

func TestCommentReporter_WriterError(t *testing.T) {
	// The stub ignores the writer, so this currently returns nil.
	// Once the real implementation lands, this should return a wrapped error.
	r := &Comment{}
	_ = r.Write(context.Background(), errWriter{}, []normalizer.Finding{})
}
