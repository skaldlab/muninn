package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skaldlab/muninn/internal/normalizer"
)

func runFakePipelineCheck() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	_, _ = os.Stdout.WriteString(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

func fakePipelineCheckExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_PIPELINE_CHECK=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

func fakePipelineCheckSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_PIPELINE_CHECK=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

func lookPathPipelineCheck() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/pipeline_check", nil }
}

func writePipelineCheckStub(t *testing.T, target string) {
	t.Helper()
	path := filepath.Join(target, "bitbucket-pipelines.yml")
	if err := os.WriteFile(path, []byte("pipelines:\n  default:\n    - step:\n        script: [echo hi]\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestPipelineCheckName(t *testing.T) {
	p := NewPipelineCheck()
	if p.Name() != "pipeline-check" {
		t.Fatalf("Name() = %q, want pipeline-check", p.Name())
	}
}

func TestPipelineCheckIsAvailable(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		p := &PipelineCheck{lookPath: lookPathPipelineCheck()}
		if !p.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		p := &PipelineCheck{lookPath: lookPathMissing()}
		if p.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestPipelineCheckRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/pipeline-check/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	target := t.TempDir()
	writePipelineCheckStub(t, target)

	p := &PipelineCheck{
		execFunc: fakePipelineCheckExecFunc(string(fixture), 1),
		lookPath: lookPathPipelineCheck(),
	}
	findings, err := p.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	f0 := findings[0]
	if f0.Tool != "pipeline-check" {
		t.Errorf("Tool = %q", f0.Tool)
	}
	if f0.RuleID != "BB-004" {
		t.Errorf("RuleID = %q, want BB-004", f0.RuleID)
	}
	if f0.Severity != normalizer.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f0.Severity)
	}
	if f0.File != "bitbucket-pipelines.yml" {
		t.Errorf("File = %q, want bitbucket-pipelines.yml", f0.File)
	}
	if f0.Fingerprint == "" {
		t.Error("Fingerprint empty")
	}
	if !strings.Contains(f0.Description, "Recommendation:") {
		t.Errorf("Description missing recommendation: %q", f0.Description)
	}
}

func TestPipelineCheckRun_NoPipelineFile(t *testing.T) {
	p := &PipelineCheck{
		execFunc: fakePipelineCheckExecFunc(`{"findings":[]}`, 0),
		lookPath: lookPathPipelineCheck(),
	}
	findings, err := p.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if findings != nil {
		t.Errorf("findings = %v, want nil when no bitbucket-pipelines.yml", findings)
	}
}

func TestPipelineCheckRun_BinaryNotFound(t *testing.T) {
	p := &PipelineCheck{
		execFunc: fakePipelineCheckExecFunc(`{}`, 0),
		lookPath: lookPathMissing(),
	}
	_, err := p.Run(context.Background(), t.TempDir())
	if err == nil || err.Error() != "pipeline-check: binary not found on PATH" {
		t.Fatalf("Run() = %v, want binary-not-found error", err)
	}
}

func TestPipelineCheckRun_Timeout(t *testing.T) {
	target := t.TempDir()
	writePipelineCheckStub(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p := &PipelineCheck{
		execFunc: fakePipelineCheckSleepExecFunc(),
		lookPath: lookPathPipelineCheck(),
	}
	_, err := p.Run(ctx, target)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestPipelineCheckSeverity(t *testing.T) {
	cases := map[string]normalizer.Severity{
		"CRITICAL": normalizer.SeverityCritical,
		"HIGH":     normalizer.SeverityHigh,
		"MEDIUM":   normalizer.SeverityMedium,
		"LOW":      normalizer.SeverityLow,
		"INFO":     normalizer.SeverityInfo,
		"other":    normalizer.SeverityInfo,
	}
	for in, want := range cases {
		if got := pipelineCheckSeverity(in); got != want {
			t.Errorf("pipelineCheckSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePipelineCheckJSON_Malformed(t *testing.T) {
	_, err := parsePipelineCheckJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNormalizePipelineCheck_Nil(t *testing.T) {
	if got := normalizePipelineCheck(nil, "."); got != nil {
		t.Errorf("normalizePipelineCheck(nil) = %v, want nil", got)
	}
}

func TestPipelineCheckRelPath(t *testing.T) {
	target := "/repo"
	got := pipelineCheckRelPath("/repo/bitbucket-pipelines.yml", target)
	if got != "bitbucket-pipelines.yml" {
		t.Errorf("rel = %q", got)
	}
	got = pipelineCheckRelPath("/elsewhere/bitbucket-pipelines.yml", target)
	if got != "bitbucket-pipelines.yml" {
		t.Errorf("basename fallback = %q", got)
	}
	got = pipelineCheckRelPath("/elsewhere/other.yml", target)
	if got != "/elsewhere/other.yml" {
		t.Errorf("absolute keep = %q", got)
	}
}

func TestParsePipelineCheckJSON_Empty(t *testing.T) {
	doc, err := parsePipelineCheckJSON(nil)
	if err != nil || doc == nil {
		t.Fatalf("empty = (%v, %v)", doc, err)
	}
	findings := normalizePipelineCheck(&pipelineCheckReport{
		Findings: []pipelineCheckFinding{{CheckID: "BB-001", Passed: true, Title: "ok"}},
	}, ".")
	if len(findings) != 0 {
		t.Fatalf("passed findings should be skipped, got %d", len(findings))
	}
}
