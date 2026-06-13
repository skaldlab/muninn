package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// TestMain handles the subprocess helper used by fakeExecFunc.
//
// When MUNINN_FAKE_GITLEAKS=1 the process is being re-invoked as a fake
// gitleaks binary: it writes MUNINN_FAKE_REPORT to the --report-path argument
// (found in os.Args) and exits with MUNINN_FAKE_EXIT. When MUNINN_FAKE_SLEEP=1
// it sleeps instead, simulating a slow subprocess for cancellation tests.
//
// When MUNINN_FAKE_ZIZMOR=1 the process is being re-invoked as a fake zizmor
// binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT.
//
// When MUNINN_FAKE_ACTIONLINT=1 the process is being re-invoked as a fake
// actionlint binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with
// MUNINN_FAKE_EXIT.
//
// When MUNINN_FAKE_POUTINE=1 the process is being re-invoked as a fake poutine
// binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT.
//
// When MUNINN_FAKE_SEMGREP=1 the process is being re-invoked as a fake semgrep
// binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT.
//
// When MUNINN_FAKE_OSV=1 the process is being re-invoked as a fake osv-scanner
// binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT.
//
// When MUNINN_FAKE_TRIVY=1 the process is being re-invoked as a fake trivy
// binary: it writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT.
//
// Future scanner test files in this package must NOT define their own TestMain;
// add a new MUNINN_FAKE_<SCANNER>=1 branch here instead.
func TestMain(m *testing.M) {
	if os.Getenv("MUNINN_FAKE_GITLEAKS") == "1" {
		runFakeGitleaks()
		return
	}
	if os.Getenv("MUNINN_FAKE_ZIZMOR") == "1" {
		runFakeZizmor()
		return
	}
	if os.Getenv("MUNINN_FAKE_ACTIONLINT") == "1" {
		runFakeActionlint()
		return
	}
	if os.Getenv("MUNINN_FAKE_POUTINE") == "1" {
		runFakePoutine()
		return
	}
	if os.Getenv("MUNINN_FAKE_SEMGREP") == "1" {
		runFakeSemgrep()
		return
	}
	if os.Getenv("MUNINN_FAKE_OSV") == "1" {
		runFakeOSV()
		return
	}
	if os.Getenv("MUNINN_FAKE_TRIVY") == "1" {
		runFakeTrivy()
		return
	}
	os.Exit(m.Run())
}

func runFakeGitleaks() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	report := os.Getenv("MUNINN_FAKE_REPORT")
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	for i, arg := range os.Args {
		if arg == "--report-path" && i+1 < len(os.Args) {
			_ = os.WriteFile(os.Args[i+1], []byte(report), 0600)
			break
		}
	}
	os.Exit(code)
}

// fakeExecFunc returns an execFunc that re-invokes the test binary as a fake
// gitleaks subprocess, writing reportJSON to --report-path and exiting with
// exitCode. No real gitleaks binary is required.
func fakeExecFunc(reportJSON string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_GITLEAKS=1",
			"MUNINN_FAKE_REPORT="+reportJSON,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeSleepExecFunc returns an execFunc whose subprocess sleeps until killed,
// used to drive timeout and cancellation tests.
func fakeSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_GITLEAKS=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

func lookPathFound() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/gitleaks", nil }
}

func lookPathMissing() func(string) (string, error) {
	return func(name string) (string, error) {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestGitleaksName(t *testing.T) {
	g := NewGitleaks()
	if g.Name() != "gitleaks" {
		t.Fatalf("Name() = %q, want %q", g.Name(), "gitleaks")
	}
}

func TestGitleaksIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		g := &Gitleaks{lookPath: lookPathFound()}
		if !g.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		g := &Gitleaks{lookPath: lookPathMissing()}
		if g.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestGitleaksRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/gitleaks/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	g := &Gitleaks{
		execFunc: fakeExecFunc(string(fixture), 1), // exit 1 = leaks found
		lookPath: lookPathFound(),
	}

	findings, err := g.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// All findings must carry the tool name.
	for i, f := range findings {
		if f.Tool != "gitleaks" {
			t.Errorf("findings[%d].Tool = %q, want %q", i, f.Tool, "gitleaks")
		}
	}

	// Finding 0: aws-access-key → critical
	if got := findings[0].Severity; got != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", got)
	}
	if got := findings[0].RuleID; got != "aws-access-key" {
		t.Errorf("findings[0].RuleID = %q, want aws-access-key", got)
	}
	if got := findings[0].File; got != "config/deploy.sh" {
		t.Errorf("findings[0].File = %q, want config/deploy.sh", got)
	}
	if got := findings[0].Line; got != 12 {
		t.Errorf("findings[0].Line = %d, want 12", got)
	}
	// Fixture supplies a fingerprint; normalizer must preserve it.
	if findings[0].Fingerprint == "" {
		t.Error("findings[0].Fingerprint is empty, want the fixture value")
	}

	// Finding 1: generic-api-token → high
	if got := findings[1].Severity; got != normalizer.SeverityHigh {
		t.Errorf("findings[1].Severity = %q, want high", got)
	}
	// Fixture has no fingerprint; normalizer must generate one.
	if findings[1].Fingerprint == "" {
		t.Error("findings[1].Fingerprint is empty, want generated value")
	}

	// Finding 2: internal-credential (no keyword match) → medium
	if got := findings[2].Severity; got != normalizer.SeverityMedium {
		t.Errorf("findings[2].Severity = %q, want medium", got)
	}
}

func TestGitleaksRun_NoFindings(t *testing.T) {
	g := &Gitleaks{
		execFunc: fakeExecFunc("[]", 0), // exit 0 = no leaks
		lookPath: lookPathFound(),
	}

	findings, err := g.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestGitleaksRun_BinaryNotFound(t *testing.T) {
	g := &Gitleaks{
		execFunc: fakeExecFunc("[]", 0),
		lookPath: lookPathMissing(),
	}

	_, err := g.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "gitleaks: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestGitleaksRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	g := &Gitleaks{
		execFunc: fakeSleepExecFunc(),
		lookPath: lookPathFound(),
	}

	_, err := g.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
