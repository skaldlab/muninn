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

func runFakeSkillSpector() {
	if os.Getenv("MUNINN_FAKE_SLEEP") == "1" {
		time.Sleep(60 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("MUNINN_FAKE_EXIT"))
	_, _ = os.Stdout.WriteString(os.Getenv("MUNINN_FAKE_STDOUT"))
	os.Exit(code)
}

func fakeSkillSpectorExecFunc(jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_SKILLSPECTOR=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

func fakeSkillSpectorSleepExecFunc() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			"MUNINN_FAKE_SKILLSPECTOR=1",
			"MUNINN_FAKE_SLEEP=1",
		)
		return cmd
	}
}

func lookPathSkillSpector() func(string) (string, error) {
	return func(string) (string, error) { return "/usr/bin/skillspector", nil }
}

func writeSkillSpectorStub(t *testing.T, target, rel string) {
	t.Helper()
	dir := filepath.Join(target, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(path, []byte("---\nname: stub\n---\n# stub\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestSkillSpectorName(t *testing.T) {
	s := NewSkillSpector()
	if s.Name() != "skillspector" {
		t.Fatalf("Name() = %q, want skillspector", s.Name())
	}
}

func TestSkillSpectorIsAvailable(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		s := &SkillSpector{lookPath: lookPathSkillSpector()}
		if !s.IsAvailable() {
			t.Error("IsAvailable() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		s := &SkillSpector{lookPath: lookPathMissing()}
		if s.IsAvailable() {
			t.Error("IsAvailable() = true, want false")
		}
	})
}

func TestSkillSpectorRun_WithFindings(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/skillspector/sample.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	target := t.TempDir()
	writeSkillSpectorStub(t, target, ".claude/skills/suspicious-sync")

	s := &SkillSpector{
		execFunc: fakeSkillSpectorExecFunc(string(fixture), 1),
		lookPath: lookPathSkillSpector(),
	}
	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	f0 := findings[0]
	if f0.Tool != "skillspector" {
		t.Errorf("Tool = %q", f0.Tool)
	}
	if f0.RuleID != "E2" {
		t.Errorf("RuleID = %q, want E2", f0.RuleID)
	}
	if f0.Severity != normalizer.SeverityHigh {
		t.Errorf("Severity = %q, want high", f0.Severity)
	}
	if f0.File != "scripts/sync.py" {
		t.Errorf("File = %q, want scripts/sync.py", f0.File)
	}
	if f0.Line != 23 {
		t.Errorf("Line = %d, want 23", f0.Line)
	}
	if f0.Title != "Env Variable Harvesting" {
		t.Errorf("Title = %q", f0.Title)
	}
	if !strings.Contains(f0.Description, "Remediation:") {
		t.Errorf("Description missing remediation: %q", f0.Description)
	}
	if f0.Fingerprint == "" {
		t.Error("Fingerprint empty")
	}
}

func TestSkillSpectorRun_NoSkills(t *testing.T) {
	s := &SkillSpector{
		execFunc: fakeSkillSpectorExecFunc(`{"issues":[]}`, 0),
		lookPath: lookPathSkillSpector(),
	}
	findings, err := s.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if findings != nil {
		t.Errorf("findings = %v, want nil when no skills present", findings)
	}
}

func TestSkillSpectorRun_BinaryNotFound(t *testing.T) {
	s := &SkillSpector{
		execFunc: fakeSkillSpectorExecFunc(`{}`, 0),
		lookPath: lookPathMissing(),
	}
	_, err := s.Run(context.Background(), t.TempDir())
	if err == nil || err.Error() != "skillspector: binary not found on PATH" {
		t.Fatalf("Run() = %v, want binary-not-found error", err)
	}
}

func TestSkillSpectorRun_Timeout(t *testing.T) {
	target := t.TempDir()
	writeSkillSpectorStub(t, target, ".claude/skills/demo")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := &SkillSpector{
		execFunc: fakeSkillSpectorSleepExecFunc(),
		lookPath: lookPathSkillSpector(),
	}
	_, err := s.Run(ctx, target)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestSkillSpectorSeverity(t *testing.T) {
	cases := map[string]normalizer.Severity{
		"CRITICAL": normalizer.SeverityCritical,
		"HIGH":     normalizer.SeverityHigh,
		"MEDIUM":   normalizer.SeverityMedium,
		"LOW":      normalizer.SeverityLow,
		"INFO":     normalizer.SeverityInfo,
		"other":    normalizer.SeverityInfo,
	}
	for in, want := range cases {
		if got := skillSpectorSeverity(in); got != want {
			t.Errorf("skillSpectorSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSkillSpectorJSON_Malformed(t *testing.T) {
	_, err := parseSkillSpectorJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseSkillSpectorJSON_Empty(t *testing.T) {
	_, err := parseSkillSpectorJSON(nil)
	if err == nil {
		t.Fatal("expected error for empty stdout")
	}
}

func TestNormalizeSkillSpector_Nil(t *testing.T) {
	if got := normalizeSkillSpector(nil); got != nil {
		t.Errorf("normalizeSkillSpector(nil) = %v, want nil", got)
	}
}

func TestNormalizeSkillSpector_RecursiveSkills(t *testing.T) {
	doc := &skillSpectorReport{
		Skills: []skillSpectorReport{{
			Issues: []skillSpectorIssue{{
				FindingID:   "P1",
				Pattern:     "Instruction Override",
				Severity:    "HIGH",
				Location:    skillSpectorLocation{File: "SKILL.md", StartLine: 3},
				Explanation: "override",
			}},
		}},
	}
	got := normalizeSkillSpector(doc)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].RuleID != "P1" || got[0].File != "SKILL.md" {
		t.Errorf("finding = %+v", got[0])
	}
}

func TestSkillSpectorRun_OutputAndExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, output, wantError string
		exitCode, wantCount     int
	}{
		{name: "successful empty output", wantError: "empty report"},
		{name: "findings exit with empty output", exitCode: 1, wantError: "empty report"},
		{name: "clean report", output: `{"issues":[]}`},
		{name: "findings on successful exit", output: `{"issues":[{"finding_id":"E2","severity":"high","location":{"file":"a.py","start_line":1}}]}`, wantCount: 1},
		{name: "malformed successful output", output: `{broken`, wantError: "parsing JSON"},
		{name: "malformed findings output", output: `{broken`, exitCode: 1, wantError: "parsing JSON"},
		{name: "scanner failure with valid JSON", output: `{"issues":[]}`, exitCode: 2, wantError: "running scanner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			writeSkillSpectorStub(t, target, ".agents/skills/demo")
			s := &SkillSpector{lookPath: lookPathSkillSpector(), execFunc: fakeSkillSpectorExecFunc(tc.output, tc.exitCode)}
			got, err := s.Run(context.Background(), target)
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

func TestSkillSpectorRun_CommandArguments(t *testing.T) {
	target := t.TempDir()
	writeSkillSpectorStub(t, target, ".claude/skills/demo")
	called := false
	s := &SkillSpector{lookPath: lookPathSkillSpector(), execFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		collection := filepath.Join(target, ".claude", "skills")
		want := []string{"scan", collection, "--no-llm", "--format", "json", "--recursive"}
		if name != "skillspector" || !reflect.DeepEqual(args, want) {
			t.Errorf("command = %s %q, want skillspector %q", name, args, want)
		}
		return fakeSkillSpectorExecFunc(`{"issues":[]}`, 0)(ctx, name, args...)
	}}
	if _, err := s.Run(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("scanner was not executed")
	}
}

func TestSkillSpectorRun_RootManifest(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# root skill\n"), 0644); err != nil {
		t.Fatal(err)
	}
	called := false
	s := &SkillSpector{lookPath: lookPathSkillSpector(), execFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		want := []string{"scan", target, "--no-llm", "--format", "json"}
		if name != "skillspector" || !reflect.DeepEqual(args, want) {
			t.Errorf("command = %s %q, want skillspector %q", name, args, want)
		}
		return fakeSkillSpectorExecFunc(`{"issues":[]}`, 0)(ctx, name, args...)
	}}
	if _, err := s.Run(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("scanner was not executed")
	}
}

func TestNormalizeOneSkillSpector_StableIdentity(t *testing.T) {
	issue := skillSpectorIssue{
		FindingID:   "E2",
		Pattern:     "Env Variable Harvesting",
		Severity:    "hIgH",
		Location:    skillSpectorLocation{File: "scripts/sync.py", StartLine: 23},
		Explanation: "explanation",
		Remediation: "fix it",
		Category:    "data_exfiltration",
		Surface:     "code",
		Confidence:  0.9,
	}
	f := normalizeOneSkillSpector(issue)
	if f.Tool != "skillspector" || f.RuleID != "E2" || f.Severity != normalizer.SeverityHigh {
		t.Errorf("finding = %+v", f)
	}
	if f.ID == "" || f.ID != f.Fingerprint {
		t.Errorf("invalid identity: %+v", f)
	}
	if f.Metadata["category"] != "data_exfiltration" {
		t.Errorf("metadata = %+v", f.Metadata)
	}
	moved := issue
	moved.Explanation = "updated"
	moved.Pattern = "Updated title"
	if normalizeOneSkillSpector(moved).Fingerprint != f.Fingerprint {
		t.Error("wording changed finding identity")
	}
	moved.FindingID = "E1"
	if normalizeOneSkillSpector(moved).Fingerprint == f.Fingerprint {
		t.Error("different rules share an identity")
	}
	issue.FindingID = ""
	issue.ID = "fallback-id"
	issue.Pattern = ""
	fb := normalizeOneSkillSpector(issue)
	if fb.RuleID != "fallback-id" || fb.Title != "fallback-id" {
		t.Errorf("fallback identity = %+v", fb)
	}
}
