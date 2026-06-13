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

// runFakeTrivy is invoked by TestMain when MUNINN_FAKE_TRIVY=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the trivy binary without requiring it to be installed.
func runFakeTrivy() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeTrivyExecFunc returns an execFunc that re-invokes the test binary as a
// fake trivy subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakeTrivyExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_TRIVY=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeTrivySleepExecFunc returns an execFunc whose subprocess sleeps until killed,
// used to drive timeout and cancellation tests.
func fakeTrivySleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_TRIVY=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathTrivy returns a fake lookPath that reports trivy as present.
func lookPathTrivy() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/trivy", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestTrivyName(t *testing.T) {
	tv := NewTrivy()
	if tv.Name() != "trivy" {
		t.Fatalf("Name() = %q, want %q", tv.Name(), "trivy")
	}
}

func TestTrivyIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		tv := &Trivy{lookPath: lookPathTrivy()}
		if !tv.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		tv := &Trivy{lookPath: lookPathMissing()}
		if tv.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestTrivyRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/trivy/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	tv := &Trivy{
		execFunc: fakeTrivyExecFunc(string(fixture), 1), // exit 1 = findings found
		lookPath: lookPathTrivy(),
	}

	findings, err := tv.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	// Fixture has 2 vulns in package-lock.json + 0 in go.sum = 2 total.
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	for i, f := range findings {
		if f.Tool != "trivy" {
			t.Errorf("findings[%d].Tool = %q, want trivy", i, f.Tool)
		}
		if f.Fingerprint == "" {
			t.Errorf("findings[%d].Fingerprint is empty", i)
		}
		if f.Line != 0 {
			t.Errorf("findings[%d].Line = %d, want 0 (no line numbers for dep scanners)", i, f.Line)
		}
		if f.Metadata == nil {
			t.Errorf("findings[%d].Metadata is nil", i)
		}
	}

	// Finding 0: CVE-2021-23337 lodash — CRITICAL.
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "CVE-2021-23337" {
		t.Errorf("findings[0].RuleID = %q, want CVE-2021-23337", f0.RuleID)
	}
	if f0.File != "package-lock.json" {
		t.Errorf("findings[0].File = %q, want package-lock.json", f0.File)
	}
	if f0.RuleURL != "https://avd.aquasec.com/nvd/cve-2021-23337" {
		t.Errorf("findings[0].RuleURL = %q", f0.RuleURL)
	}
	if f0.Metadata["pkg_name"] != "lodash" {
		t.Errorf("findings[0].Metadata[pkg_name] = %v, want lodash", f0.Metadata["pkg_name"])
	}
	if f0.Metadata["fixed_version"] != "4.17.21" {
		t.Errorf("findings[0].Metadata[fixed_version] = %v, want 4.17.21", f0.Metadata["fixed_version"])
	}

	// Finding 1: CVE-2020-28500 lodash — HIGH.
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[1].Severity = %q, want high", f1.Severity)
	}
	if f1.RuleID != "CVE-2020-28500" {
		t.Errorf("findings[1].RuleID = %q, want CVE-2020-28500", f1.RuleID)
	}
}

func TestTrivyRun_NoFindings(t *testing.T) {
	tv := &Trivy{
		execFunc: fakeTrivyExecFunc(`{"Results":[]}`, 0),
		lookPath: lookPathTrivy(),
	}

	findings, err := tv.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestTrivyRun_BinaryNotFound(t *testing.T) {
	tv := &Trivy{
		execFunc: fakeTrivyExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := tv.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "trivy: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestTrivyRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	tv := &Trivy{
		execFunc: fakeTrivySleepExecFunc(),
		lookPath: lookPathTrivy(),
	}

	_, err := tv.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
