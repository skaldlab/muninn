package reporter

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

func TestCommentReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "✅ No security issues found") {
		t.Errorf("empty output missing clean-scan message, got:\n%s", out)
	}
	if !strings.Contains(out, "[Muninn](https://github.com/skaldlab/muninn)") {
		t.Error("empty output missing footer link")
	}
	if !strings.Contains(out, "[Skald Lab](https://skaldlab.dev)") {
		t.Error("empty output missing Skald Lab link")
	}
	if strings.Contains(out, "<a href=") || strings.Contains(out, "---") {
		t.Error("footer should use markdown only, no HTML or horizontal rules")
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
	out := buf.String()
	if !strings.Contains(out, "🔴 Critical") {
		t.Error("output missing critical section header")
	}
	if !strings.Contains(out, "🟠 High") {
		t.Error("output missing high section header")
	}
	if !strings.Contains(out, "Exposed secret") {
		t.Error("output missing critical finding title")
	}
	if !strings.Contains(out, "[Skald Lab](https://skaldlab.dev)") {
		t.Error("output missing footer")
	}
}

func TestCommentReporter_GroupsBySeverity(t *testing.T) {
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
	out := buf.String()
	// Critical must appear before High in output order.
	critPos := strings.Index(out, "🔴 Critical")
	highPos := strings.Index(out, "🟠 High")
	if critPos < 0 || highPos < 0 || critPos > highPos {
		t.Errorf("severity sections out of order: critical at %d, high at %d", critPos, highPos)
	}
}

func TestCommentReporter_TruncatesLongDescription(t *testing.T) {
	// Use 301 bytes to trigger truncation (limit is 300).
	long := strings.Repeat("x", 301)
	f := normalizer.Finding{
		ID: "z", Severity: normalizer.SeverityMedium,
		Description: long, Fingerprint: "z",
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, []normalizer.Finding{f}); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	// The truncated description must end with "..." and not contain the full 301 chars.
	if !strings.Contains(out, strings.Repeat("x", 300)+"...") {
		t.Error("description was not truncated to 300 chars + ellipsis")
	}
	if strings.Contains(out, strings.Repeat("x", 301)) {
		t.Error("full 301-char description should not appear in output")
	}
}

func TestCommentReporter_OmitsSuppressedFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityCritical, Title: "real bug", Fingerprint: "a"},
		{ID: "b", Severity: normalizer.SeverityCritical, Title: "fixture noise",
			Fingerprint: "b", Suppressed: true},
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "fixture noise") {
		t.Error("suppressed finding should not appear in PR comment")
	}
	if !strings.Contains(out, "real bug") {
		t.Error("non-suppressed finding should appear in PR comment")
	}
	if strings.Contains(out, "| 🔴 Critical | 2 |") {
		t.Error("summary should count only visible findings")
	}
}

func TestCommentReporter_SuppressedGroupsOmitted(t *testing.T) {
	// A severity group that would otherwise appear should be absent if all
	// findings in it are suppressed — unless non-suppressed siblings exist.
	// Here: only a low finding; no medium findings at all — medium section absent.
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityLow, Fingerprint: "a"},
	}
	var buf bytes.Buffer
	r := &Comment{}
	if err := r.Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Medium Findings") {
		t.Error("medium section should be absent when there are no medium findings")
	}
}

func TestCommentReporter_WriterError(t *testing.T) {
	r := &Comment{}
	if err := r.Write(context.Background(), errWriter{}, []normalizer.Finding{}); err == nil {
		t.Fatal("Write() with failing writer expected error, got nil")
	}
}
