package reporter

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// countingErrWriter succeeds for the first ok writes, then fails. It lets a test
// drive a reporter partway through rendering before a write fails.
type countingErrWriter struct {
	ok int
	n  int
}

func (w *countingErrWriter) Write(p []byte) (int, error) {
	if w.n >= w.ok {
		return 0, errors.New("simulated write error")
	}
	w.n++
	return len(p), nil
}

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

func TestCommentReporter_ShowsMergedDependencyFinding(t *testing.T) {
	findings := []normalizer.Finding{{
		ID: "f1", Tool: "osv-scanner", Severity: normalizer.SeverityHigh,
		Title: "Command Injection in lodash", RuleID: "GHSA-35jh-r3h4-6jhm",
		File: "package-lock.json", Fingerprint: "f1",
		DetectedBy: []string{"osv-scanner", "trivy"},
		Sources: []normalizer.FindingSource{
			{Tool: "osv-scanner", File: "package-lock.json"},
			{Tool: "trivy", File: "node:18 (npm)"},
		},
		Metadata: map[string]any{
			"package": "lodash", "version": "4.17.20", "ecosystem": "npm",
			"aliases": []string{"CVE-2021-23337"},
		},
	}}
	var buf bytes.Buffer
	if err := (&Comment{}).Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"#### [dependency] Command Injection in lodash",
		"**Package:** `lodash` 4.17.20 (npm)",
		"**Advisory:** `GHSA-35jh-r3h4-6jhm` (CVE-2021-23337)",
		"**Detected by:** osv-scanner, trivy",
		"**Sources:**",
		"- `package-lock.json` (osv-scanner)",
		"- `node:18 (npm)` (trivy)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("merged dependency comment missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[osv-scanner]") || strings.Contains(out, "[trivy]") {
		t.Errorf("aggregated finding must not be attributed to one scanner in the title:\n%s", out)
	}
}

func TestCommentReporter_DependencyFindingPropagatesWriteErrors(t *testing.T) {
	f := normalizer.Finding{
		ID: "f1", Tool: "osv-scanner", Severity: normalizer.SeverityHigh,
		Title: "Command Injection in lodash", RuleID: "GHSA-35jh-r3h4-6jhm",
		File: "package-lock.json", Fingerprint: "f1",
		DetectedBy: []string{"osv-scanner", "trivy"},
		Sources: []normalizer.FindingSource{
			{Tool: "osv-scanner", File: "package-lock.json"},
			{Tool: "trivy", File: "node:18"},
		},
		Metadata: map[string]any{"package": "lodash", "version": "4.17.20", "ecosystem": "npm"},
	}
	// Fail at each successive write so every error-return branch in the
	// dependency renderer (heading, package, advisory, sources, description) runs.
	for ok := 0; ok < 15; ok++ {
		w := &countingErrWriter{ok: ok}
		if err := (&Comment{}).Write(context.Background(), w, []normalizer.Finding{f}); err == nil {
			t.Errorf("ok=%d: expected write error to propagate", ok)
		}
	}
}

func TestCommentReporter_SingleScannerDependencyFinding(t *testing.T) {
	findings := []normalizer.Finding{{
		ID: "f1", Tool: "trivy", Severity: normalizer.SeverityHigh,
		Title: "openssl buffer overflow", RuleID: "CVE-2021-0001",
		File: "node:18", Fingerprint: "f1",
		Metadata: map[string]any{"pkg_name": "openssl", "installed_version": "1.1.1"},
	}}
	var buf bytes.Buffer
	if err := (&Comment{}).Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"#### [dependency] openssl buffer overflow",
		"**Package:** `openssl` 1.1.1",
		"**Advisory:** `CVE-2021-0001`",
		"**Detected by:** trivy",
		"**Source:** `node:18` (trivy)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("single-scanner dependency comment missing %q:\n%s", want, out)
		}
	}
	// A lone CVE id should not be repeated as a parenthetical alias.
	if strings.Contains(out, "(CVE-2021-0001)") {
		t.Errorf("native CVE should not be duplicated as an alias:\n%s", out)
	}
}

func TestCommentReporter_DescriptionCannotBreakLayout(t *testing.T) {
	findings := []normalizer.Finding{{
		ID: "f1", Tool: "osv-scanner", Severity: normalizer.SeverityHigh,
		Title: "lodash ReDoS", RuleID: "GHSA-29mw-wpgm-hmr9", File: "package-lock.json",
		Fingerprint: "f1",
		Description: "Steps to reproduce:\n```js\nvar lo = require('lodash');\n```\n### Impact\nbad things happen",
	}}
	var buf bytes.Buffer
	if err := (&Comment{}).Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "```") {
		t.Errorf("description code fences must be neutralized, got:\n%s", out)
	}
	if !strings.Contains(out, "Powered by [Muninn]") {
		t.Errorf("footer missing — description broke the comment layout:\n%s", out)
	}
}

func TestCommentReporter_NonDependencyFindingKeepsToolPrefix(t *testing.T) {
	// Findings without a published advisory (secrets, SAST, IaC) stay attributed
	// to their single scanner and never grow a Detected by / Sources block.
	findings := []normalizer.Finding{{
		ID: "f1", Tool: "gitleaks", Severity: normalizer.SeverityHigh,
		Title: "AWS key leaked", RuleID: "aws-access-key", File: "main.go", Line: 5,
		Fingerprint: "f1",
	}}
	var buf bytes.Buffer
	if err := (&Comment{}).Write(context.Background(), &buf, findings); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "#### [gitleaks] AWS key leaked") {
		t.Errorf("non-dependency finding should keep its [tool] prefix:\n%s", out)
	}
	if strings.Contains(out, "Detected by:") || strings.Contains(out, "**Source") {
		t.Errorf("non-dependency finding should not show detected-by/sources block:\n%s", out)
	}
}
