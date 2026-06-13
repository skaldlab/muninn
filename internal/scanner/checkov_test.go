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

// runFakeCheckov is invoked by TestMain when MUNINN_FAKE_CHECKOV=1.
// It writes MUNINN_FAKE_STDOUT to stdout and exits with MUNINN_FAKE_EXIT,
// simulating the checkov binary without requiring it to be installed.
func runFakeCheckov() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	fmt.Print(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

// fakeCheckovExecFunc returns an execFunc that re-invokes the test binary as a
// fake checkov subprocess, writing jsonStr to stdout and exiting with exitCode.
func fakeCheckovExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_CHECKOV=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// fakeCheckovSleepExecFunc returns an execFunc whose subprocess sleeps until
// killed, used to drive timeout and cancellation tests.
func fakeCheckovSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_CHECKOV=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

// lookPathCheckov returns a fake lookPath that reports checkov as present.
func lookPathCheckov() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/checkov", nil }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestCheckovName(t *testing.T) {
	ck := NewCheckov()
	if ck.Name() != "checkov" {
		t.Fatalf("Name() = %q, want %q", ck.Name(), "checkov")
	}
}

func TestCheckovIsAvailable(t *testing.T) {
	t.Run("binary present", func(t *testing.T) {
		ck := &Checkov{lookPath: lookPathCheckov()}
		if !ck.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("binary absent", func(t *testing.T) {
		ck := &Checkov{lookPath: lookPathMissing()}
		if ck.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestCheckovRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/checkov/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	ck := &Checkov{
		execFunc: fakeCheckovExecFunc(string(fixture), 1), // exit 1 = failures found
		lookPath: lookPathCheckov(),
	}

	findings, err := ck.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	// Fixture: 2 terraform failed + 1 kubernetes failed = 3 total.
	// passed_checks and skipped_checks must be ignored.
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	for i, f := range findings {
		if f.Tool != "checkov" {
			t.Errorf("findings[%d].Tool = %q, want checkov", i, f.Tool)
		}
		if f.Fingerprint == "" {
			t.Errorf("findings[%d].Fingerprint is empty", i)
		}
		if f.Metadata == nil {
			t.Errorf("findings[%d].Metadata is nil", i)
		}
	}

	// Finding 0: CKV_AWS_18 — MEDIUM.
	f0 := findings[0]
	if f0.Severity != normalizer.SeverityMedium {
		t.Errorf("findings[0].Severity = %q, want medium", f0.Severity)
	}
	if f0.RuleID != "CKV_AWS_18" {
		t.Errorf("findings[0].RuleID = %q, want CKV_AWS_18", f0.RuleID)
	}
	if f0.File != "infra/main.tf" {
		t.Errorf("findings[0].File = %q, want infra/main.tf", f0.File)
	}
	if f0.Line != 1 {
		t.Errorf("findings[0].Line = %d, want 1 (file_line_range[0])", f0.Line)
	}
	if f0.RuleURL != "https://docs.bridgecrew.io/docs/s3_13-enable-logging" {
		t.Errorf("findings[0].RuleURL = %q", f0.RuleURL)
	}
	if f0.Metadata["resource"] != "aws_s3_bucket.data" {
		t.Errorf("findings[0].Metadata[resource] = %v", f0.Metadata["resource"])
	}
	if f0.Metadata["check_type"] != "terraform" {
		t.Errorf("findings[0].Metadata[check_type] = %v", f0.Metadata["check_type"])
	}

	// Finding 1: CKV_AWS_19 — CRITICAL.
	f1 := findings[1]
	if f1.Severity != normalizer.SeverityCritical {
		t.Errorf("findings[1].Severity = %q, want critical", f1.Severity)
	}

	// Finding 2: CKV_K8S_30 — HIGH, from kubernetes framework.
	f2 := findings[2]
	if f2.Severity != normalizer.SeverityHigh {
		t.Errorf("findings[2].Severity = %q, want high", f2.Severity)
	}
	if f2.Metadata["check_type"] != "kubernetes" {
		t.Errorf("findings[2].Metadata[check_type] = %v, want kubernetes", f2.Metadata["check_type"])
	}
}

func TestCheckovRun_ArrayOutput(t *testing.T) {
	// Confirm the array form (leading '[') is handled correctly.
	const fixture = `[{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_1","bc_check_id":"BC_AWS_1","check_name":"Test check","file_path":"main.tf","file_line_range":[5,10],"resource":"aws_s3_bucket.test","severity":"HIGH","guideline":"https://example.com"}]}}]`

	ck := &Checkov{
		execFunc: fakeCheckovExecFunc(fixture, 1),
		lookPath: lookPathCheckov(),
	}

	findings, err := ck.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != normalizer.SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestCheckovRun_SingleObjectOutput(t *testing.T) {
	// Confirm the single-object form (leading '{') is normalised to []checkovBlock.
	const fixture = `{"check_type":"cloudformation","results":{"failed_checks":[{"check_id":"CKV_AWS_2","bc_check_id":"BC_AWS_2","check_name":"CF test check","file_path":"template.yaml","file_line_range":[3,8],"resource":"AWS::S3::Bucket","severity":"MEDIUM","guideline":"https://example.com/cf"}]}}`

	ck := &Checkov{
		execFunc: fakeCheckovExecFunc(fixture, 1),
		lookPath: lookPathCheckov(),
	}

	findings, err := ck.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Metadata["check_type"] != "cloudformation" {
		t.Errorf("check_type = %v, want cloudformation", findings[0].Metadata["check_type"])
	}
}

func TestCheckovRun_NoFindings(t *testing.T) {
	ck := &Checkov{
		execFunc: fakeCheckovExecFunc(`[{"check_type":"terraform","results":{"failed_checks":[]}}]`, 0),
		lookPath: lookPathCheckov(),
	}

	findings, err := ck.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestCheckovRun_BinaryNotFound(t *testing.T) {
	ck := &Checkov{
		execFunc: fakeCheckovExecFunc("{}", 0),
		lookPath: lookPathMissing(),
	}

	_, err := ck.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() expected an error when binary is missing, got nil")
	}
	const want = "checkov: binary not found on PATH"
	if err.Error() != want {
		t.Errorf("Run() error = %q, want %q", err.Error(), want)
	}
}

func TestCheckovRun_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ck := &Checkov{
		execFunc: fakeCheckovSleepExecFunc(),
		lookPath: lookPathCheckov(),
	}

	_, err := ck.Run(ctx, ".")
	if err == nil {
		t.Fatal("Run() expected an error on timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want DeadlineExceeded or Canceled", err)
	}
}
