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

// runFakePoutine is invoked by TestMain when MUNINN_FAKE_POUTINE=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the poutine binary without requiring it to be installed.
func runFakePoutine() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakePoutineExecFunc returns an execFunc that re-invokes the test binary as a
// fake poutine subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakePoutineExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_POUTINE=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakePoutineSleepExecFunc returns an execFunc whose subprocess sleeps until
// killed, used to drive timeout and cancellation tests.
func fakePoutineSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_POUTINE=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathPoutine returns a fake lookPath that reports poutine as present.
func lookPathPoutine() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/poutine", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestPoutineName(t *testing.T) {
	p := NewPoutine()
	if p.Name() != "poutine" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "poutine")
	}
}

func TestPoutineIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		p := &Poutine{lookPath: lookPathPoutine()}
		if !p.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		p := &Poutine{lookPath: lookPathMissing()}
		if p.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestPoutineRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/poutine/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	p := &Poutine{
		execFunc: fakePoutineExecFunc(string(fixture), 0), // poutine exits 0 always
		lookPath: lookPathPoutine(),
	}

	// "." always exists; Run() will proceed to execute poutine.
	findings, err := p.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// All findings must carry the tool name.
	for i, f := range findings {
		if f.Tool != "poutine" {
			t.Errorf("findings[%d].Tool = %q, want %q", i, f.Tool, "poutine")
		}
	}

	// Finding 0: injection, level=error → critical; path resolved via blobshas.
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.RuleID != "injection" {
		t.Errorf("findings[0].RuleID = %q, want injection", f0.RuleID)
	}
	if f0.File != ".github/workflows/ci.yml" {
		t.Errorf("findings[0].File = %q, want .github/workflows/ci.yml", f0.File)
	}
	if f0.Line != 24 {
		t.Errorf("findings[0].Line = %d, want 24", f0.Line)
	}
	if f0.Description != "run: echo ${{ github.event.pull_request.title }}" {
		t.Errorf("findings[0].Description = %q, want meta.details", f0.Description)
	}
	if f0.Fingerprint == "" {
		t.Error("findings[0].Fingerprint is empty, want generated value")
	}
	const wantURL0 = "https://github.com/boostsecurityio/poutine/blob/main/docs/rules/injection.md"
	if f0.RuleURL != wantURL0 {
		t.Errorf("findings[0].RuleURL = %q, want %q", f0.RuleURL, wantURL0)
	}

	// Finding 1: dangerous-workflow-trigger, level=error → critical.
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[1].Severity = %q, want critical", f1.Severity)
	}
	if f1.Fingerprint == "" {
		t.Error("findings[1].Fingerprint is empty, want generated value")
	}

	// Finding 2: unpinned-action, level=warning → medium.
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[2].Severity = %q, want medium", f2.Severity)
	}
}

func TestPoutineRun_SkipsEmptyFindings(t *testing.T) {
	const doc = `{"rules":{},"findings":[{"rule_id":"","meta":{}},{"rule_id":"x","meta":{}}]}`
	p := &Poutine{
		execFunc: fakePoutineExecFunc(doc, 0),
		lookPath: lookPathPoutine(),
	}
	findings, err := p.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (empty rule_id skipped)", len(findings))
	}
	if findings[0].RuleID != "x" {
		t.Errorf("RuleID = %q, want x", findings[0].RuleID)
	}
}

func TestNormalizeLegacyPoutineFormat(t *testing.T) {
	const legacy = `{
		"findings":[{
			"rule":{"id":"injection","title":"Injection","description":"desc","severity":"high"},
			"occurrence":{"file":"workflow.yml","startLine":10,"startColumn":1},
			"fingerprint":"legacy-fp"
		}]
	}`
	doc, err := parsePoutineJSON([]byte(legacy))
	if err != nil {
		t.Fatalf("parsePoutineJSON: %v", err)
	}
	out := normalizePoutine(doc)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].RuleID != "injection" || out[0].File != "workflow.yml" || out[0].Fingerprint != "legacy-fp" {
		t.Errorf("legacy finding = %+v", out[0])
	}
}

func TestPoutineRun_NoFindings(t *testing.T) {
	p := &Poutine{
		execFunc: fakePoutineExecFunc(`{"findings":[]}`, 0),
		lookPath: lookPathPoutine(),
	}

	findings, err := p.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestPoutineRun_BinaryNotFound(t *testing.T) {
	p := &Poutine{
		execFunc: fakePoutineExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := p.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "poutine: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestPoutineRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	p := &Poutine{
		execFunc: fakePoutineSleepExecFunc(),
		lookPath: lookPathPoutine(),
	}

	_, err := p.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
