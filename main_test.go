package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/scanner"
)

// chdirTemp changes the working directory to a fresh temp dir for the duration
// of the test, then restores the original cwd in t.Cleanup.
// scan() writes muninn.json and muninn.sarif to cwd, so tests must isolate it.
func chdirTemp(t *testing.T) string {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return dir
}

// ── envOr ─────────────────────────────────────────────────────────────────────

func TestEnvOr_EnvSet(t *testing.T) {
	t.Setenv("MUNINN_TEST_KEY", "value-from-env")
	if got := envOr("MUNINN_TEST_KEY", "fallback"); got != "value-from-env" {
		t.Errorf("envOr = %q, want value-from-env", got)
	}
}

func TestEnvOr_EnvUnset(t *testing.T) {
	os.Unsetenv("MUNINN_TEST_KEY_UNSET")
	if got := envOr("MUNINN_TEST_KEY_UNSET", "fallback"); got != "fallback" {
		t.Errorf("envOr = %q, want fallback", got)
	}
}

func TestEnvOr_EmptyEnvUseFallback(t *testing.T) {
	// An empty string env var is treated as unset by envOr.
	t.Setenv("MUNINN_TEST_EMPTY", "")
	if got := envOr("MUNINN_TEST_EMPTY", "default"); got != "default" {
		t.Errorf("envOr(empty) = %q, want default", got)
	}
}

// ── splitFormats ──────────────────────────────────────────────────────────────

func TestSplitFormats(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"json", []string{"json"}},
		{"json,sarif", []string{"json", "sarif"}},
		{"json, sarif , comment", []string{"json", "sarif", "comment"}},
		{"", []string{}},
		{" , ", []string{}},
	}
	for _, tc := range cases {
		got := splitFormats(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitFormats(%q): len=%d, want %d", tc.input, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitFormats(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// ── writeJSON ─────────────────────────────────────────────────────────────────

func TestWriteJSON_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := writeJSON(path, nil); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// nil slice marshals to "null"; that is acceptable for empty output.
	if len(data) == 0 {
		t.Error("writeJSON wrote empty file")
	}
}

func TestWriteJSON_WithFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Tool: "gitleaks", Severity: normalizer.SeverityHigh, Fingerprint: "f1"},
	}
	path := filepath.Join(t.TempDir(), "out.json")
	if err := writeJSON(path, findings); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var report struct {
		Findings []normalizer.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Tool != "gitleaks" {
		t.Errorf("unexpected findings: %+v", report.Findings)
	}
}

// ── writeSARIF ────────────────────────────────────────────────────────────────

func TestWriteSARIF_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := writeSARIF(path, nil); err != nil {
		t.Fatalf("writeSARIF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Must be valid JSON with the SARIF schema fields.
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Error("SARIF must contain at least one run")
	}
}

func TestWriteSARIF_WithFindings(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Tool: "trivy", Severity: normalizer.SeverityCritical, Fingerprint: "f1"},
	}
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := writeSARIF(path, findings); err != nil {
		t.Fatalf("writeSARIF: %v", err)
	}
}

// ── scan (orchestrator) ───────────────────────────────────────────────────────

func TestScanOrchestrator_NoScannersAvailable(t *testing.T) {
	// In the test environment none of the 8 scanner binaries are on PATH, so
	// scan() skips them all and writes the output files cleanly.
	dir := chdirTemp(t)
	cfg := config.Defaults()
	if err := scan(context.Background(), cfg, dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
	// muninn.json must have been written.
	if _, err := os.Stat("muninn.json"); err != nil {
		t.Errorf("muninn.json not created: %v", err)
	}
}

func TestScanOrchestrator_MultipleFormats(t *testing.T) {
	dir := chdirTemp(t)
	cfg := config.Defaults()
	if err := scan(context.Background(), cfg, dir, "json,sarif"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
	for _, name := range []string{"muninn.json", "muninn.sarif"} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("%s not created: %v", name, err)
		}
	}
}

func TestScanOrchestrator_FailOnThreshold(t *testing.T) {
	// With no scanners available there are zero findings, so the fail-on check
	// passes and scan() returns nil even at a "high" threshold.
	dir := chdirTemp(t)
	cfg := config.Defaults()
	cfg.FailOn = "high"
	if err := scan(context.Background(), cfg, dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

func TestScanOrchestrator_BelowThreshold(t *testing.T) {
	dir := chdirTemp(t)
	cfg := config.Defaults()
	cfg.FailOn = "critical"
	if err := scan(context.Background(), cfg, dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

func TestScanOrchestrator_CommentFormat(t *testing.T) {
	dir := chdirTemp(t)
	cfg := config.Defaults()
	// "comment" format logs a not-yet-implemented message; must not error.
	if err := scan(context.Background(), cfg, dir, "comment"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

// ── writeJSON / writeSARIF error paths ────────────────────────────────────────

func TestWriteJSON_BadPath(t *testing.T) {
	if err := writeJSON("/nonexistent-dir/out.json", nil); err == nil {
		t.Fatal("writeJSON to bad path expected error, got nil")
	}
}

func TestWriteSARIF_BadPath(t *testing.T) {
	if err := writeSARIF("/nonexistent-dir/out.sarif", nil); err == nil {
		t.Fatal("writeSARIF to bad path expected error, got nil")
	}
}

// ── scanner "available" path in scan() ───────────────────────────────────────

// addFakeScannerToPath writes a minimal shell script at tmpdir/<name> and
// prepends tmpdir to PATH.  The script emits stdout and exits with exitCode,
// which is enough to exercise the "scanner available" branches in scan().
func addFakeScannerToPath(t *testing.T, name, stdout string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, name)
	// Use printf to avoid echo's inconsistent newline behaviour across shells.
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %s\nexit %d\n",
		shellQuote(stdout), exitCode)
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary %s: %v", name, err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// shellQuote wraps s in single quotes, escaping any single quotes inside.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func TestScanOrchestrator_PoutineAvailable_Success(t *testing.T) {
	// Put a fake "poutine" on PATH that returns an empty findings document.
	// Exercises the `if po.IsAvailable()` true branch and the success path.
	addFakeScannerToPath(t, "poutine", `{"findings":[]}`, 0)
	dir := chdirTemp(t)
	if err := scan(context.Background(), config.Defaults(), dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

func TestScanOrchestrator_PoutineAvailable_Error(t *testing.T) {
	// Malformed JSON output causes poutine.Run() to return an error.
	// scan() must log it and continue, not propagate it.
	addFakeScannerToPath(t, "poutine", `{bad json}`, 0)
	dir := chdirTemp(t)
	if err := scan(context.Background(), config.Defaults(), dir, "json"); err != nil {
		t.Fatalf("scan() must not propagate scanner errors, got: %v", err)
	}
}

func TestScanOrchestrator_SemgrepAvailable_Success(t *testing.T) {
	addFakeScannerToPath(t, "semgrep", `{"results":[],"errors":[]}`, 0)
	dir := chdirTemp(t)
	if err := scan(context.Background(), config.Defaults(), dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

func TestScanOrchestrator_OSVAvailable_Success(t *testing.T) {
	addFakeScannerToPath(t, "osv-scanner", `{"results":[]}`, 0)
	dir := chdirTemp(t)
	if err := scan(context.Background(), config.Defaults(), dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

func TestScanOrchestrator_TrivyAvailable_Success(t *testing.T) {
	addFakeScannerToPath(t, "trivy", `{"Results":[]}`, 0)
	dir := chdirTemp(t)
	if err := scan(context.Background(), config.Defaults(), dir, "json"); err != nil {
		t.Fatalf("scan() unexpected error: %v", err)
	}
}

// ── run() ─────────────────────────────────────────────────────────────────────

// setArgs temporarily replaces os.Args for the duration of the test.
func setArgs(t *testing.T, args ...string) {
	t.Helper()
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })
	os.Args = append([]string{"muninn"}, args...)
}

func TestRun_NoArgs(t *testing.T) {
	chdirTemp(t)
	setArgs(t)
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_WithTargetAndOutput(t *testing.T) {
	dir := chdirTemp(t)
	setArgs(t, "--target", dir, "--output", "json")
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_WithSARIFOutput(t *testing.T) {
	dir := chdirTemp(t)
	setArgs(t, "--target", dir, "--output", "sarif")
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_WithMultipleFormats(t *testing.T) {
	dir := chdirTemp(t)
	setArgs(t, "--target", dir, "--output", "json,sarif")
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_WithFailOnFlag(t *testing.T) {
	dir := chdirTemp(t)
	setArgs(t, "--target", dir, "--fail-on", "high", "--output", "json")
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_FromEnvVars(t *testing.T) {
	dir := chdirTemp(t)
	t.Setenv("SCAN_TARGET", dir)
	t.Setenv("OUTPUT_FORMATS", "json")
	t.Setenv("FAIL_ON", "critical")
	setArgs(t)
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	setArgs(t, "--does-not-exist")
	if code := run(); code != 2 {
		t.Errorf("run() with unknown flag = %d, want 2", code)
	}
}

func TestRun_WithConfigFlag(t *testing.T) {
	// Config file doesn't exist; run() falls back to defaults (no error).
	dir := chdirTemp(t)
	setArgs(t, "--config", filepath.Join(dir, "muninn.yml"), "--target", dir, "--output", "json")
	if code := run(); code != 0 {
		t.Errorf("run() = %d, want 0", code)
	}
}

// ── severityRank ──────────────────────────────────────────────────────────────

func TestSeverityRank(t *testing.T) {
	// Ranks must be strictly ordered: critical > high > medium > low > info.
	order := []normalizer.Severity{
		normalizer.SeverityInfo,
		normalizer.SeverityLow,
		normalizer.SeverityMedium,
		normalizer.SeverityHigh,
		normalizer.SeverityCritical,
	}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i]) <= severityRank(order[i-1]) {
			t.Errorf("severityRank(%q) should be greater than severityRank(%q)", order[i], order[i-1])
		}
	}
	// An unknown severity ranks below info.
	if severityRank(normalizer.Severity("bogus")) != 0 {
		t.Errorf("severityRank(bogus) = %d, want 0", severityRank(normalizer.Severity("bogus")))
	}
}

// ── checkFailOn ───────────────────────────────────────────────────────────────

func TestCheckFailOn_AboveThreshold(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityCritical, Fingerprint: "a"},
	}
	if err := checkFailOn("high", findings); err == nil {
		t.Fatal("checkFailOn expected error when a finding is above threshold, got nil")
	}
}

func TestCheckFailOn_AtThreshold(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityHigh, Fingerprint: "a"},
	}
	if err := checkFailOn("high", findings); err == nil {
		t.Fatal("checkFailOn expected error when a finding equals threshold, got nil")
	}
}

func TestCheckFailOn_BelowThreshold(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityLow, Fingerprint: "a"},
		{ID: "b", Severity: normalizer.SeverityMedium, Fingerprint: "b"},
	}
	if err := checkFailOn("high", findings); err != nil {
		t.Fatalf("checkFailOn unexpected error for sub-threshold findings: %v", err)
	}
}

func TestCheckFailOn_NoThreshold(t *testing.T) {
	// An empty threshold disables the check regardless of severity.
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityCritical, Fingerprint: "a"},
	}
	if err := checkFailOn("", findings); err != nil {
		t.Fatalf("checkFailOn with empty threshold should be nil, got: %v", err)
	}
}

func TestCheckFailOn_SuppressedIgnored(t *testing.T) {
	// Suppressed findings must not count toward the fail-on threshold.
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityCritical, Suppressed: true, Fingerprint: "a"},
	}
	if err := checkFailOn("critical", findings); err != nil {
		t.Fatalf("checkFailOn should ignore suppressed findings, got: %v", err)
	}
}

// ── activeScanners ────────────────────────────────────────────────────────────

func TestActiveScanners_Count(t *testing.T) {
	scanners := activeScanners()
	if len(scanners) != 8 {
		t.Fatalf("activeScanners() returned %d scanners, want 8", len(scanners))
	}
	// Every scanner must report a non-empty name.
	for i, sc := range scanners {
		if sc.Name() == "" {
			t.Errorf("scanner at index %d has empty Name()", i)
		}
	}
}

// ── runScanner ────────────────────────────────────────────────────────────────

func TestRunScanner_DisabledInConfig(t *testing.T) {
	// A scanner marked disabled in config is skipped even when its fake binary
	// is on PATH; runScanner must return nil findings without executing it.
	addFakeScannerToPath(t, "poutine", `{"findings":[{"rule":{"id":"x","severity":"critical"}}]}`, 0)
	cfg := config.Defaults()
	cfg.Scanners["poutine"] = config.ScannerConfig{Enabled: false}

	got := runScanner(context.Background(), scanner.NewPoutine(), t.TempDir(), cfg)
	if got != nil {
		t.Errorf("runScanner for disabled scanner = %v, want nil", got)
	}
}

func TestRunScanner_EnabledRuns(t *testing.T) {
	// A scanner enabled in config with an available fake binary runs and its
	// findings are returned.
	addFakeScannerToPath(t, "poutine", `{"findings":[]}`, 0)
	cfg := config.Defaults()

	got := runScanner(context.Background(), scanner.NewPoutine(), t.TempDir(), cfg)
	if got != nil && len(got) != 0 {
		t.Errorf("runScanner = %v, want empty", got)
	}
}

// ── applySuppressions ─────────────────────────────────────────────────────────

func TestApplySuppressions_MatchingPathID(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", File: "testdata/fixture-repo/src/app.py", Fingerprint: "fp-1"},
		{ID: "f2", File: "internal/scanner/gitleaks.go", Fingerprint: "fp-2"},
	}
	suppressions := []config.Suppression{
		{ID: "testdata/fixture-repo", Reason: "integration fixture"},
	}

	got := applySuppressions(findings, suppressions)

	if !got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = false, want true (path matched fixture prefix)")
	}
	if got[1].Suppressed {
		t.Errorf("findings[1].Suppressed = true, want false (path outside fixture)")
	}
}

func TestApplySuppressions_MatchingFingerprint(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
		{ID: "f2", Fingerprint: "fp-xyz", Severity: normalizer.SeverityMedium},
	}
	suppressions := []config.Suppression{
		{Fingerprint: "fp-abc", Reason: "false positive"},
	}

	got := applySuppressions(findings, suppressions)

	if len(got) != 2 {
		t.Fatalf("applySuppressions returned %d findings, want 2", len(got))
	}
	if !got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = false, want true (fingerprint matched)")
	}
	if got[1].Suppressed {
		t.Errorf("findings[1].Suppressed = true, want false (fingerprint did not match)")
	}
}

func TestApplySuppressions_NoMatch(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
	}
	suppressions := []config.Suppression{
		{Fingerprint: "fp-other", Reason: "unrelated"},
	}

	got := applySuppressions(findings, suppressions)

	if got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = true, want false (no fingerprint match)")
	}
}

func TestApplySuppressions_Expired(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
	}
	past := time.Now().Add(-24 * time.Hour)
	suppressions := []config.Suppression{
		{Fingerprint: "fp-abc", Reason: "expired", Expires: past},
	}

	got := applySuppressions(findings, suppressions)

	if got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = true, want false (suppression is expired)")
	}
}

func TestApplySuppressions_NotYetExpired(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
	}
	future := time.Now().Add(24 * time.Hour)
	suppressions := []config.Suppression{
		{Fingerprint: "fp-abc", Reason: "still active", Expires: future},
	}

	got := applySuppressions(findings, suppressions)

	if !got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = false, want true (suppression not yet expired)")
	}
}

func TestApplySuppressions_NoSuppressions(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
	}

	got := applySuppressions(findings, nil)

	if got[0].Suppressed {
		t.Errorf("findings[0].Suppressed = true, want false (no suppressions)")
	}
}

func TestApplySuppressions_DoesNotMutateInput(t *testing.T) {
	original := []normalizer.Finding{
		{ID: "f1", Fingerprint: "fp-abc", Severity: normalizer.SeverityHigh},
	}
	suppressions := []config.Suppression{
		{Fingerprint: "fp-abc", Reason: "test"},
	}

	_ = applySuppressions(original, suppressions)

	if original[0].Suppressed {
		t.Error("applySuppressions mutated the input slice")
	}
}

// ── shouldFail (checkFailOn) ──────────────────────────────────────────────────

func TestShouldFail_AboveThreshold(t *testing.T) {
	// A critical finding with fail-on=high must trigger failure.
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "f1", Severity: normalizer.SeverityCritical},
	}
	if err := checkFailOn("high", findings); err == nil {
		t.Fatal("expected error for critical finding above 'high' threshold, got nil")
	}
}

func TestShouldFail_BelowThreshold(t *testing.T) {
	// A medium finding with fail-on=high must not trigger failure.
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "f1", Severity: normalizer.SeverityMedium},
	}
	if err := checkFailOn("high", findings); err != nil {
		t.Fatalf("expected nil for medium finding below 'high' threshold, got: %v", err)
	}
}

func TestShouldFail_Suppressed(t *testing.T) {
	// A suppressed critical finding must not trigger failure even at critical threshold.
	findings := []normalizer.Finding{
		{ID: "f1", Fingerprint: "f1", Severity: normalizer.SeverityCritical, Suppressed: true},
	}
	if err := checkFailOn("critical", findings); err != nil {
		t.Fatalf("expected nil for suppressed critical finding, got: %v", err)
	}
}
