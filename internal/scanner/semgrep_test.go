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

// runFakeSemgrep is invoked by TestMain when MUNINN_FAKE_SEMGREP=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the semgrep binary without requiring it to be installed.
func runFakeSemgrep() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeSemgrepExecFunc returns an execFunc that re-invokes the test binary as a
// fake semgrep subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakeSemgrepExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_SEMGREP=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeSemgrepSleepExecFunc returns an execFunc whose subprocess sleeps until
// killed, used to drive timeout and cancellation tests.
func fakeSemgrepSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_SEMGREP=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathSemgrep returns a fake lookPath that reports semgrep as present.
func lookPathSemgrep() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/semgrep", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestSemgrepName(t *testing.T) {
	s := NewSemgrep()
	if s.Name() != "semgrep" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "semgrep")
	}
}

func TestSemgrepIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		s := &Semgrep{lookPath: lookPathSemgrep()}
		if !s.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		s := &Semgrep{lookPath: lookPathMissing()}
		if s.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestSemgrepRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/semgrep/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	s := &Semgrep{
		execFunc: fakeSemgrepExecFunc(string(fixture), 1), // exit 1 = findings found
		lookPath: lookPathSemgrep(),
	}

	findings, err := s.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	for i, f := range findings {
		if f.Tool != "semgrep" {
			t.Errorf("findings[%d].Tool = %q, want semgrep", i, f.Tool)
		}
	}

	// Finding 0: ERROR + HIGH impact + HIGH confidence → critical; fixture fingerprint preserved.
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "python.lang.security.audit.exec-use.exec-use" {
		t.Errorf("findings[0].RuleID = %q", f0.RuleID)
	}
	if f0.File != "src/app.py" {
		t.Errorf("findings[0].File = %q, want src/app.py", f0.File)
	}
	if f0.Line != 10 {
		t.Errorf("findings[0].Line = %d, want 10", f0.Line)
	}
	if f0.Fingerprint != "a1b2c3d4e5f60001" {
		t.Errorf("findings[0].Fingerprint = %q, want a1b2c3d4e5f60001", f0.Fingerprint)
	}
	// Title must be the last check_id segment with separators replaced.
	if f0.Title != "exec use" {
		t.Errorf("findings[0].Title = %q, want \"exec use\"", f0.Title)
	}
	// RuleURL sourced from metadata.references[0].
	const wantURL0 = "https://semgrep.dev/r/python.lang.security.audit.exec-use"
	if f0.RuleURL != wantURL0 {
		t.Errorf("findings[0].RuleURL = %q, want %q", f0.RuleURL, wantURL0)
	}

	// Finding 1: ERROR + MEDIUM confidence → high; fingerprint generated.
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[1].Severity = %q, want high", f1.Severity)
	}
	if f1.Fingerprint == "" {
		t.Error("findings[1].Fingerprint is empty, want generated value")
	}

	// Finding 2: WARNING → medium; fingerprint generated.
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[2].Severity = %q, want medium", f2.Severity)
	}
	if f2.Fingerprint == "" {
		t.Error("findings[2].Fingerprint is empty, want generated value")
	}
}

func TestSemgrepRun_CriticalUpgrade(t *testing.T) {
	// Minimal fixture with ERROR + HIGH impact + HIGH confidence to confirm the
	// upgrade path independently of the full sample fixture.
	const fixture = `{"results":[{"check_id":"test.pkg.critical-rule","path":"test.go","start":{"line":1,"col":1},"end":{"line":1,"col":10},"extra":{"message":"critical","severity":"ERROR","fingerprint":"","metadata":{"confidence":"HIGH","impact":"HIGH","references":[]}}}],"errors":[]}`

	s := &Semgrep{
		execFunc: fakeSemgrepExecFunc(fixture, 1),
		lookPath: lookPathSemgrep(),
	}

	findings, err := s.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != normalizer.SeverityCritical {
		t.Errorf("Severity = %q, want critical (upgrade from ERROR+HIGH+HIGH)", findings[0].Severity)
	}
	// Title should be last segment: "critical rule"
	if findings[0].Title != "critical rule" {
		t.Errorf("Title = %q, want \"critical rule\"", findings[0].Title)
	}
}

func TestSemgrepRun_NoFindings(t *testing.T) {
	s := &Semgrep{
		execFunc: fakeSemgrepExecFunc(`{"results":[],"errors":[]}`, 0),
		lookPath: lookPathSemgrep(),
	}

	findings, err := s.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestSemgrepRun_FatalError(t *testing.T) {
	// Exit code 2 = semgrep fatal error; must be surfaced as a Go error.
	s := &Semgrep{
		execFunc: fakeSemgrepExecFunc("", 2),
		lookPath: lookPathSemgrep(),
	}

	_, err := s.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error for exit code 2, got nil")
	}
	if !errors.Is(err, &exec.ExitError{}) {
		// Just confirm the error string contains the scanner prefix.
		if len(err.Error()) < 8 || err.Error()[:8] != "semgrep:" {
			t.Errorf("Run() error = %q, want semgrep: prefix", err.Error())
		}
	}
}

func TestSemgrepRun_BinaryNotFound(t *testing.T) {
	s := &Semgrep{
		execFunc: fakeSemgrepExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := s.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "semgrep: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestSemgrepRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	s := &Semgrep{
		execFunc: fakeSemgrepSleepExecFunc(),
		lookPath: lookPathSemgrep(),
	}

	_, err := s.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
