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

// runFakeZizmor is invoked by TestMain when MUNINN_FAKE_ZIZMOR=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the zizmor binary without requiring it to be installed.
func runFakeZizmor() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeZizmorExecFunc returns an execFunc that re-invokes the test binary as a
// fake zizmor subprocess, writing sarifJSON to stdout and exiting with exitCode.
func fakeZizmorExecFunc(sarifJSON string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_ZIZMOR=1",
			"MUNINN_FAKE_STDOUT="+sarifJSON,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeZizmorSleepExecFunc returns an execFunc whose subprocess sleeps until
// killed, used to drive timeout and cancellation tests.
func fakeZizmorSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_ZIZMOR=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestZizmorName(t *testing.T) {
	z := NewZizmor()
	if z.Name() != "zizmor" {
		t.Fatalf("Name() = %q, want %q", z.Name(), "zizmor")
	}
}

func TestZizmorIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		z := &Zizmor{lookPath: func(string) (string, error) { return "/usr/bin/zizmor", nil }}
		if !z.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		z := &Zizmor{lookPath: lookPathMissing()}
		if z.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestZizmorRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/zizmor/sample.sarif")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	z := &Zizmor{
		execFunc: fakeZizmorExecFunc(string(fixture), 1), // exit 1 = findings found
		lookPath: func(string) (string, error) { return "/usr/bin/zizmor", nil },
	}

	findings, err := z.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// All findings must carry the tool name.
	for i, f := range findings {
		if f.Tool != "zizmor" {
			t.Errorf("findings[%d].Tool = %q, want %q", i, f.Tool, "zizmor")
		}
	}

	// Finding 0: pull-request-target, level=error → critical
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "pull-request-target" {
		t.Errorf("findings[0].RuleID = %q, want pull-request-target", f0.RuleID)
	}
	if f0.File != ".github/workflows/deploy.yml" {
		t.Errorf("findings[0].File = %q, want .github/workflows/deploy.yml", f0.File)
	}
	if f0.Line != 5 {
		t.Errorf("findings[0].Line = %d, want 5", f0.Line)
	}
	// Fixture supplies a fingerprint; normalizer must preserve it.
	if f0.Fingerprint != "a1b2c3d4e5f60001" {
		t.Errorf("findings[0].Fingerprint = %q, want a1b2c3d4e5f60001", f0.Fingerprint)
	}
	// RuleURL must be sourced from the rules array helpUri.
	const wantURL0 = "https://woodruffw.github.io/zizmor/audits/pull-request-target"
	if f0.RuleURL != wantURL0 {
		t.Errorf("findings[0].RuleURL = %q, want %q", f0.RuleURL, wantURL0)
	}

	// Finding 1: unpinned-uses, level=warning → high, no fingerprint in fixture
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[1].Severity = %q, want high", f1.Severity)
	}
	if f1.Fingerprint == "" {
		t.Error("findings[1].Fingerprint is empty, want generated value")
	}

	// Finding 2: excessive-permissions, level=note → medium
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[2].Severity = %q, want medium", f2.Severity)
	}
	if f2.Fingerprint != "f0e1d2c3b4a50003" {
		t.Errorf("findings[2].Fingerprint = %q, want f0e1d2c3b4a50003", f2.Fingerprint)
	}
}

func TestZizmorRun_NoFindings(t *testing.T) {
	empty := `{"runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}`
	z := &Zizmor{
		execFunc: fakeZizmorExecFunc(empty, 0), // exit 0 = no findings
		lookPath: func(string) (string, error) { return "/usr/bin/zizmor", nil },
	}

	findings, err := z.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestZizmorRun_BinaryNotFound(t *testing.T) {
	z := &Zizmor{
		execFunc: fakeZizmorExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := z.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "zizmor: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestZizmorRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	z := &Zizmor{
		execFunc: fakeZizmorSleepExecFunc(),
		lookPath: func(string) (string, error) { return "/usr/bin/zizmor", nil },
	}

	_, err := z.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
