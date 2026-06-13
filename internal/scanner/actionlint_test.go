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

// runFakeActionlint is invoked by TestMain when MUNINN_FAKE_ACTIONLINT=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the actionlint binary without requiring it to be installed.
func runFakeActionlint() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeActionlintExecFunc returns an execFunc that re-invokes the test binary as
// a fake actionlint subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakeActionlintExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_ACTIONLINT=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeActionlintSleepExecFunc returns an execFunc whose subprocess sleeps until
// killed, used to drive timeout and cancellation tests.
func fakeActionlintSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_ACTIONLINT=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathActionlint returns a fake lookPath that reports actionlint as present.
func lookPathActionlint() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/actionlint", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestActionlintName(t *testing.T) {
	a := NewActionlint()
	if a.Name() != "actionlint" {
		t.Fatalf("Name() = %q, want %q", a.Name(), "actionlint")
	}
}

func TestActionlintIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		a := &Actionlint{lookPath: lookPathActionlint()}
		if !a.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		a := &Actionlint{lookPath: lookPathMissing()}
		if a.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestActionlintRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/actionlint/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	// Provide a target with a real .github/workflows directory so Run() does
	// not short-circuit before invoking the fake binary.
	target := t.TempDir()
	if err := os.MkdirAll(target+"/.github/workflows", 0755); err != nil {
		t.Fatalf("creating workflows dir: %v", err)
	}

	a := &Actionlint{
		execFunc: fakeActionlintExecFunc(string(fixture), 1), // exit 1 = findings found
		lookPath: lookPathActionlint(),
	}

	findings, err := a.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// All findings must carry the tool name.
	for i, f := range findings {
		if f.Tool != "actionlint" {
			t.Errorf("findings[%d].Tool = %q, want %q", i, f.Tool, "actionlint")
		}
	}

	// Finding 0: expression-injection, severity=error → critical
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "expression-injection" {
		t.Errorf("findings[0].RuleID = %q, want expression-injection", f0.RuleID)
	}
	if f0.File != ".github/workflows/ci.yml" {
		t.Errorf("findings[0].File = %q, want .github/workflows/ci.yml", f0.File)
	}
	if f0.Line != 24 {
		t.Errorf("findings[0].Line = %d, want 24", f0.Line)
	}
	// Actionlint never supplies fingerprints; normalizer must always generate one.
	if f0.Fingerprint == "" {
		t.Error("findings[0].Fingerprint is empty, want generated value")
	}
	if f0.RuleURL != "https://rhysd.github.io/actionlint/" {
		t.Errorf("findings[0].RuleURL = %q, want https://rhysd.github.io/actionlint/", f0.RuleURL)
	}

	// Finding 1: action, severity=warning → high
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[1].Severity = %q, want high", f1.Severity)
	}
	if f1.Fingerprint == "" {
		t.Error("findings[1].Fingerprint is empty, want generated value")
	}

	// Finding 2: shellcheck, severity=info → medium
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[2].Severity = %q, want medium", f2.Severity)
	}
	if f2.Fingerprint == "" {
		t.Error("findings[2].Fingerprint is empty, want generated value")
	}
}

func TestActionlintRun_NoWorkflows(t *testing.T) {
	// t.TempDir() creates a real directory with no .github/workflows subtree.
	target := t.TempDir()
	a := &Actionlint{
		execFunc: fakeActionlintExecFunc("[]", 0),
		lookPath: lookPathActionlint(),
	}

	findings, err := a.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestActionlintRun_NoFindings(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(target+"/.github/workflows", 0755); err != nil {
		t.Fatalf("creating workflows dir: %v", err)
	}

	a := &Actionlint{
		execFunc: fakeActionlintExecFunc("[]", 0), // exit 0 = no findings
		lookPath: lookPathActionlint(),
	}

	findings, err := a.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestActionlintRun_BinaryNotFound(t *testing.T) {
	a := &Actionlint{
		execFunc: fakeActionlintExecFunc("[]", 0),
		lookPath: lookPathMissing(),
	}

	_, err := a.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "actionlint: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestActionlintRun_Timeout(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(target+"/.github/workflows", 0755); err != nil {
		t.Fatalf("creating workflows dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	a := &Actionlint{
		execFunc: fakeActionlintSleepExecFunc(),
		lookPath: lookPathActionlint(),
	}

	_, err := a.Run(ctx, target)
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
