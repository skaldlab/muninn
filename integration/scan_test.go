//go:build integration

package integration_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

const (
	jsonReportFile  = "muninn.json"
	sarifReportFile = "muninn.sarif"
)

var (
	repoRoot    string
	fixtureRepo string
	muninnBin   string
)

// requiredScanners lists binaries that must be on PATH for integration tests.
var requiredScanners = []string{
	"gitleaks",
	"zizmor",
	"actionlint",
	"semgrep",
	"checkov",
}

func TestMain(m *testing.M) {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: find repo root: %v\n", err)
		os.Exit(1)
	}
	repoRoot = root
	fixtureRepo = filepath.Join(repoRoot, "testdata", "fixture-repo")

	bin, err := buildMuninnBinary(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: build muninn: %v\n", err)
		os.Exit(1)
	}
	muninnBin = bin

	os.Exit(m.Run())
}

// findRepoRoot returns the repository root by walking up from the working dir.
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}

// buildMuninnBinary compiles the muninn CLI into a temp directory.
func buildMuninnBinary(root string) (string, error) {
	dir, err := os.MkdirTemp("", "muninn-integration-*")
	if err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}
	bin := filepath.Join(dir, "muninn")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, out)
	}
	return bin, nil
}

// requireScanners skips the test when any required scanner binary is missing.
func requireScanners(t *testing.T) {
	t.Helper()
	for _, name := range requiredScanners {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("skipping integration test: %s not on PATH", name)
		}
	}
}

// runResult holds the outcome of a muninn subprocess invocation.
type runResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	WorkDir  string
}

// runMuninn executes muninn with the given args from a fresh temp directory.
func runMuninn(t *testing.T, args ...string) runResult {
	t.Helper()
	workDir := t.TempDir()
	cmd := exec.Command(muninnBin, args...)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	res := runResult{WorkDir: workDir, Stdout: string(out), Stderr: string(out)}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res
		}
		t.Fatalf("muninn failed to start: %v\n%s", err, out)
	}
	return res
}

// jsonReport mirrors the JSON reporter envelope for parsing muninn.json.
type jsonReport struct {
	Version  string               `json:"version"`
	Tool     string               `json:"tool"`
	Summary  jsonReportSummary    `json:"summary"`
	Findings []normalizer.Finding `json:"findings"`
}

type jsonReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// sarifDocument mirrors the SARIF fields needed for integration assertions.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID string `json:"ruleId"`
}

// baseArgs returns common CLI flags for scanning the fixture repo.
func baseArgs(extra ...string) []string {
	args := []string{
		"--target", fixtureRepo,
		"--config", filepath.Join(fixtureRepo, "muninn.yml"),
	}
	return append(args, extra...)
}

// readJSONReport loads and parses muninn.json from the run work directory.
func readJSONReport(t *testing.T, res runResult) jsonReport {
	t.Helper()
	path := filepath.Join(res.WorkDir, jsonReportFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nstdout/stderr:\n%s", path, err, res.Stdout)
	}
	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing JSON report: %v", err)
	}
	return report
}

// readSARIFReport loads and parses muninn.sarif from the run work directory.
func readSARIFReport(t *testing.T, res runResult) sarifDocument {
	t.Helper()
	path := filepath.Join(res.WorkDir, sarifReportFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nstdout/stderr:\n%s", path, err, res.Stdout)
	}
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing SARIF report: %v", err)
	}
	return doc
}

// countByTool returns how many findings came from the given scanner.
func countByTool(findings []normalizer.Finding, tool string) int {
	n := 0
	for _, f := range findings {
		if f.Tool == tool {
			n++
		}
	}
	return n
}

// findingText returns a lowercase string combining searchable finding fields.
func findingText(f normalizer.Finding) string {
	return strings.ToLower(strings.Join([]string{
		f.Tool, f.RuleID, f.Title, f.Description, f.File,
	}, " "))
}

// hasFindingMatching reports whether any finding from tool matches the predicate.
func hasFindingMatching(findings []normalizer.Finding, tool string, match func(string) bool) bool {
	for _, f := range findings {
		if f.Tool != tool {
			continue
		}
		if match(findingText(f)) {
			return true
		}
	}
	return false
}

// TestFullScan runs Muninn against the fixture repo and verifies known
// vulnerabilities are detected end-to-end.
func TestFullScan(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(), "--output", "json")...)
	report := readJSONReport(t, res)

	if res.ExitCode != 0 && res.ExitCode != 1 {
		t.Fatalf("muninn exit code = %d, want 0 or 1 (fail-on may trigger)", res.ExitCode)
	}

	if report.Summary.Total <= 5 {
		t.Errorf("summary.total = %d, want > 5", report.Summary.Total)
	}

	checks := []struct {
		tool    string
		matches func(string) bool
		desc    string
	}{
		{"gitleaks", func(s string) bool {
			return strings.Contains(s, "stripe") || strings.Contains(s, "secret") ||
				strings.Contains(s, "sendgrid") || strings.Contains(s, "github")
		}, "committed secret"},
		{"zizmor", func(s string) bool {
			return strings.Contains(s, "pull_request_target") || strings.Contains(s, "unpinned")
		}, "pull_request_target or unpinned action"},
		{"actionlint", func(s string) bool { return true }, "any actionlint finding"},
		{"semgrep", func(s string) bool {
			return strings.Contains(s, "shell") || strings.Contains(s, "exec") || strings.Contains(s, "subprocess")
		}, "shell=True or exec usage"},
		{"checkov", func(s string) bool {
			return strings.Contains(s, "s3") || strings.Contains(s, "public") || strings.Contains(s, "ckv_aws")
		}, "public S3 bucket"},
	}

	for _, tc := range checks {
		if count := countByTool(report.Findings, tc.tool); count == 0 {
			t.Errorf("expected at least 1 %s finding (%s), got 0", tc.tool, tc.desc)
			continue
		}
		if !hasFindingMatching(report.Findings, tc.tool, tc.matches) {
			t.Errorf("expected %s finding matching %q", tc.tool, tc.desc)
		}
	}
}

// TestFullScan_JSONOutput verifies the JSON report structure and fingerprints.
func TestFullScan_JSONOutput(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(), "--format", "json")...)
	report := readJSONReport(t, res)

	if report.Summary.Total <= 0 {
		t.Errorf("summary.total = %d, want > 0", report.Summary.Total)
	}
	if report.Summary.Critical <= 0 {
		t.Errorf("summary.critical = %d, want > 0", report.Summary.Critical)
	}
	if report.Tool != "muninn" {
		t.Errorf("tool = %q, want muninn", report.Tool)
	}

	for i, f := range report.Findings {
		if f.Fingerprint == "" {
			t.Errorf("findings[%d].Fingerprint is empty (tool=%s rule=%s)", i, f.Tool, f.RuleID)
		}
	}
}

// TestFullScan_SARIFOutput verifies SARIF 2.1.0 output from a full scan.
func TestFullScan_SARIFOutput(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(), "--format", "sarif")...)
	doc := readSARIFReport(t, res)

	if doc.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", doc.Version)
	}
	if doc.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("SARIF schema = %q, want sarif-2.1.0.json", doc.Schema)
	}
	if len(doc.Runs) == 0 {
		t.Fatal("SARIF runs is empty")
	}
	if doc.Runs[0].Tool.Driver.Name != "Muninn" {
		t.Errorf("tool.driver.name = %q, want Muninn", doc.Runs[0].Tool.Driver.Name)
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Error("SARIF results is empty, want findings from fixture repo")
	}
}

// TestFullScan_FailOnCritical expects a non-zero exit when critical findings exist.
func TestFullScan_FailOnCritical(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(), "--output", "json", "--fail-on", "critical")...)
	if res.ExitCode == 0 {
		t.Fatal("muninn exit code = 0, want non-zero for --fail-on critical")
	}
	readJSONReport(t, res)
}

// TestFullScan_FailOnInfo expects a non-zero exit at the lowest severity threshold.
func TestFullScan_FailOnInfo(t *testing.T) {
	requireScanners(t)

	res := runMuninn(t, append(baseArgs(), "--output", "json", "--fail-on", "info")...)
	if res.ExitCode == 0 {
		t.Fatal("muninn exit code = 0, want non-zero for --fail-on info")
	}
}
