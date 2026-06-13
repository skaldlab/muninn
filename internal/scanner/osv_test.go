package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// runFakeOSV is invoked by TestMain when MUNINN_FAKE_OSV=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the osv-scanner binary without requiring it to be installed.
func runFakeOSV() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeOSVExecFunc returns an execFunc that re-invokes the test binary as a
// fake osv-scanner subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakeOSVExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_OSV=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeOSVSleepExecFunc returns an execFunc whose subprocess sleeps until killed,
// used to drive timeout and cancellation tests.
func fakeOSVSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_OSV=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathOSV returns a fake lookPath that reports osv-scanner as present.
func lookPathOSV() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/osv-scanner", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestOSVName(t *testing.T) {
	o := NewOSVScanner()
	if o.Name() != "osv-scanner" {
		t.Fatalf("Name() = %q, want %q", o.Name(), "osv-scanner")
	}
}

func TestOSVIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		o := &OSVScanner{lookPath: lookPathOSV()}
		if !o.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		o := &OSVScanner{lookPath: lookPathMissing()}
		if o.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestOSVRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/osv/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	o := &OSVScanner{
		execFunc: fakeOSVExecFunc(string(fixture), 1), // exit 1 = findings found
		lookPath: lookPathOSV(),
	}

	findings, err := o.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	// Fixture has 2 lodash vulns + 1 requests vuln = 3 total.
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	for i, f := range findings {
		if f.Tool != "osv-scanner" {
			t.Errorf("findings[%d].Tool = %q, want osv-scanner", i, f.Tool)
		}
		if f.Fingerprint == "" {
			t.Errorf("findings[%d].Fingerprint is empty", i)
		}
		if f.Metadata == nil {
			t.Errorf("findings[%d].Metadata is nil", i)
		}
	}

	// Finding 0: lodash GHSA-35jh-r3h4-6jhm — database_specific.severity = CRITICAL.
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("findings[0].RuleID = %q, want GHSA-35jh-r3h4-6jhm", f0.RuleID)
	}
	if f0.File != "package-lock.json" {
		t.Errorf("findings[0].File = %q, want package-lock.json", f0.File)
	}
	if f0.Line != 0 {
		t.Errorf("findings[0].Line = %d, want 0 (lockfile scanners have no line number)", f0.Line)
	}
	// RuleURL must be the first ADVISORY or WEB reference.
	const wantURL0 = "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
	if f0.RuleURL != wantURL0 {
		t.Errorf("findings[0].RuleURL = %q, want %q", f0.RuleURL, wantURL0)
	}
	// Metadata must include package fields.
	if f0.Metadata["package"] != "lodash" {
		t.Errorf("findings[0].Metadata[package] = %v, want lodash", f0.Metadata["package"])
	}
	if f0.Metadata["ecosystem"] != "npm" {
		t.Errorf("findings[0].Metadata[ecosystem] = %v, want npm", f0.Metadata["ecosystem"])
	}

	// Finding 1: lodash GHSA-jf85-cpcp-j695 — database_specific.severity = MODERATE.
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[1].Severity = %q, want medium", f1.Severity)
	}

	// Finding 2: requests GHSA-j8r2-6x86-q33q — no database_specific.severity,
	// CVSS numeric score 8.1 → high.
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[2].Severity = %q, want high (CVSS score 8.1)", f2.Severity)
	}
	if f2.File != "requirements.txt" {
		t.Errorf("findings[2].File = %q, want requirements.txt", f2.File)
	}
}

func TestOSVRun_CVSSFallback(t *testing.T) {
	// Fixture with no database_specific.severity; CVSS score 9.8 → critical.
	const fixture = `{"results":[{"source":{"path":"go.sum","type":"lockfile"},"packages":[{"package":{"name":"example-lib","version":"1.0.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GHSA-test-0001","summary":"Critical test vuln","details":"Details here.","severity":[{"type":"CVSS_V3","score":"9.8"}],"aliases":["CVE-2024-0001"],"references":[{"type":"WEB","url":"https://example.com/advisory"}],"database_specific":{"severity":""}}]}]}]}`

	o := &OSVScanner{
		execFunc: fakeOSVExecFunc(fixture, 1),
		lookPath: lookPathOSV(),
	}

	findings, err := o.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != normalizer.SeverityCritical {
		t.Errorf("Severity = %q, want critical (CVSS 9.8)", findings[0].Severity)
	}
}

func TestOSVRun_NoFindings(t *testing.T) {
	o := &OSVScanner{
		execFunc: fakeOSVExecFunc(`{"results":[]}`, 0),
		lookPath: lookPathOSV(),
	}

	findings, err := o.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestOSVRun_BinaryNotFound(t *testing.T) {
	o := &OSVScanner{
		execFunc: fakeOSVExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := o.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "osv-scanner: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestOSVRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	o := &OSVScanner{
		execFunc: fakeOSVSleepExecFunc(),
		lookPath: lookPathOSV(),
	}

	_, err := o.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
