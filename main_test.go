package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
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
	var got []normalizer.Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 1 || got[0].Tool != "gitleaks" {
		t.Errorf("unexpected findings: %+v", got)
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
	// fail-on evaluation is not yet implemented (TODO in scan()); scan() returns
	// nil regardless of findings. This test documents current behaviour.
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
