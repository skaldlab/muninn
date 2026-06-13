package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// errWriter is an io.Writer that always returns an error, used to test
// that reporters propagate writer failures to the caller.
type errWriter struct{}

func (e errWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write error")
}

func TestJSONReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &JSON{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	// json.Encoder encodes nil and empty slice differently; the reporter receives
	// []Finding{} so the output must be a JSON array (not "null").
	out := strings.TrimSpace(buf.String())
	if out == "null" {
		t.Error("empty findings should encode as [] not null")
	}
	// Must be valid JSON array.
	var arr []normalizer.Finding
	if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
		t.Errorf("output is not valid JSON array: %v", err)
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

	var got []normalizer.Finding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Tool != "gitleaks" {
		t.Errorf("Tool = %q, want gitleaks", got[0].Tool)
	}
	if got[0].Severity != normalizer.SeverityHigh {
		t.Errorf("Severity = %q, want high", got[0].Severity)
	}
}

func TestJSONReporter_MultipleFindings(t *testing.T) {
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

	var got []normalizer.Finding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// Order must be preserved.
	for i, want := range []string{"a", "b", "c"} {
		if got[i].ID != want {
			t.Errorf("findings[%d].ID = %q, want %q", i, got[i].ID, want)
		}
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

	var got []normalizer.Finding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for i, want := range sevs {
		if got[i].Severity != want {
			t.Errorf("findings[%d].Severity = %q, want %q", i, got[i].Severity, want)
		}
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
