package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	_, err := parsePipelineCheckJSON(nil)
	if err == nil {
		t.Fatal("expected error for empty stdout")
	}
	findings := normalizePipelineCheck(&pipelineCheckReport{
		Findings: []pipelineCheckFinding{{CheckID: "BB-001", Passed: true, Title: "ok"}},
	}, ".")
	if len(findings) != 0 {
		t.Fatalf("passed findings should be skipped, got %d", len(findings))
	}
}

// Exit code 1 means findings, but it must not hide a corrupt scanner report.
func TestPipelineCheckRun_OutputAndExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, output, wantError string
		exitCode, wantCount     int
	}{
		{name: "successful empty output", wantError: "empty report"},
		{name: "findings exit with empty output", exitCode: 1, wantError: "empty report"},
		{name: "clean report", output: `{"findings":[]}`},
		{name: "findings on successful exit", output: `{"findings":[{"check_id":"BB-001","severity":"high"}]}`, wantCount: 1},
		{name: "malformed successful output", output: `{broken`, wantError: "parsing JSON"},
		{name: "malformed findings output", output: `{broken`, exitCode: 1, wantError: "parsing JSON"},
		{name: "scanner failure with valid JSON", output: `{"findings":[]}`, exitCode: 2, wantError: "running scanner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			writePipelineCheckStub(t, target)
			p := &PipelineCheck{lookPath: lookPathPipelineCheck(), execFunc: fakePipelineCheckExecFunc(tc.output, tc.exitCode)}
			got, err := p.Run(context.Background(), target)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Run() error = %v, want %q", err, tc.wantError)
				}
				if len(got) != 0 {
					t.Errorf("failed scan returned findings: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.wantCount {
				t.Errorf("got %d findings, want %d", len(got), tc.wantCount)
			}
		})
	}
}

func TestPipelineCheckRun_CommandArguments(t *testing.T) {
	target := t.TempDir()
	writePipelineCheckStub(t, target)
	called := false
	p := &PipelineCheck{lookPath: lookPathPipelineCheck(), execFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		want := []string{"--pipeline", "bitbucket", "--bitbucket-path", target, "--output", "json", "--output-file", "-", "--no-chains"}
		if name != "pipeline_check" || !reflect.DeepEqual(args, want) {
			t.Errorf("command = %s %q, want pipeline_check %q", name, args, want)
		}
		return fakePipelineCheckExecFunc(`{"findings":[]}`, 0)(ctx, name, args...)
	}}
	if _, err := p.Run(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("scanner was not executed")
	}
}

func TestNormalizePipelineCheck_MixedResultsAndStableIdentity(t *testing.T) {
	input := pipelineCheckFinding{CheckID: "BB-001", Title: "Unsafe pipeline", Severity: "hIgH", Resource: "/first/bitbucket-pipelines.yml", Description: "description", Recommendation: "fix it"}
	doc := &pipelineCheckReport{Findings: []pipelineCheckFinding{{Passed: true, CheckID: "BB-PASS"}, input}}
	got := normalizePipelineCheck(doc, "/first")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Title != input.Title || f.Tool != "pipeline-check" || f.RuleID != input.CheckID || f.Severity != normalizer.SeverityHigh || f.File != "bitbucket-pipelines.yml" || f.Line != 0 {
		t.Errorf("normalized finding = %+v", f)
	}
	if f.Description != "description\n\nRecommendation: fix it" {
		t.Errorf("description = %q", f.Description)
	}
	if f.RuleURL != "https://dmartinochoa.github.io/pipeline-check/providers/bitbucket/" {
		t.Errorf("rule URL = %q", f.RuleURL)
	}
	if f.ID == "" || f.ID != f.Fingerprint {
		t.Errorf("invalid identity: %+v", f)
	}
	input.Resource = "/second/bitbucket-pipelines.yml"
	input.Title = "Updated title"
	input.Description = "updated description"
	input.Recommendation = ""
	moved := normalizeOnePipelineCheck(input, "/second")
	if moved.Fingerprint != f.Fingerprint {
		t.Error("checkout location or wording changed finding identity")
	}
	if moved.Description != input.Description {
		t.Errorf("description without recommendation = %q", moved.Description)
	}
	input.CheckID = "BB-002"
	if normalizeOnePipelineCheck(input, "/second").Fingerprint == f.Fingerprint {
		t.Error("different rules share an identity")
	}
	input.CheckID = "BB-001"
	input.Resource = "/second/nested/bitbucket-pipelines.yml"
	if normalizeOnePipelineCheck(input, "/second").Fingerprint == f.Fingerprint {
		t.Error("different files share an identity")
	}
}

func TestPipelineCheckRun_IncompleteScan(t *testing.T) {
	target := t.TempDir()
	writePipelineCheckStub(t, target)
	payload := `{"scan_status":{"complete":false,"reason":"parse failed"},"findings":[]}`
	p := &PipelineCheck{
		execFunc: fakePipelineCheckExecFunc(payload, 0),
		lookPath: lookPathPipelineCheck(),
	}
	_, err := p.Run(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "scan incomplete") {
		t.Fatalf("Run() = %v, want incomplete-scan error", err)
	}
}
