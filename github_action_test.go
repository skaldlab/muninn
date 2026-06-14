package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

func TestWriteGitHubOutputs_NotInActions(t *testing.T) {
	os.Unsetenv("GITHUB_OUTPUT")
	counts := findingCounts{Total: 3, Critical: 1, High: 2}
	if err := writeGitHubOutputs(counts, localSARIFPath, localJSONPath); err != nil {
		t.Fatalf("writeGitHubOutputs() = %v, want nil", err)
	}
}

func TestWriteGitHubOutputs_InActions(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "github_output")
	if err := os.WriteFile(outputFile, nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_OUTPUT", outputFile)

	counts := findingCounts{Total: 5, Critical: 1, High: 2, Medium: 1, Low: 1}
	if err := writeGitHubOutputs(counts, localSARIFPath, localJSONPath); err != nil {
		t.Fatalf("writeGitHubOutputs() = %v", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	checks := map[string]string{
		"findings-count": "5",
		"critical-count": "1",
		"high-count":     "2",
		"medium-count":   "1",
		"low-count":      "1",
		"sarif-path":     localSARIFPath,
		"json-path":      localJSONPath,
	}
	for key, want := range checks {
		line := key + "=" + want
		if !strings.Contains(content, line) {
			t.Errorf("GITHUB_OUTPUT missing %q\ngot:\n%s", line, content)
		}
	}
}

func TestCountActiveFindings_AllSeverities(t *testing.T) {
	findings := []normalizer.Finding{
		{Severity: normalizer.SeverityCritical},
		{Severity: normalizer.SeverityHigh},
		{Severity: normalizer.SeverityMedium},
		{Severity: normalizer.SeverityLow},
		{Severity: normalizer.SeverityInfo},
	}
	got := countActiveFindings(findings)
	if got.Total != 5 || got.Critical != 1 || got.High != 1 || got.Medium != 1 || got.Low != 1 {
		t.Errorf("countActiveFindings() = %+v, want all severities counted", got)
	}
}

func TestWriteGitHubOutputs_BadPath(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", "/nonexistent-dir/output")
	if err := writeGitHubOutputs(findingCounts{Total: 1}, localSARIFPath, localJSONPath); err == nil {
		t.Fatal("expected error writing to invalid GITHUB_OUTPUT path")
	}
}

func TestCountActiveFindings_SkipsSuppressed(t *testing.T) {
	findings := []normalizer.Finding{
		{Severity: normalizer.SeverityCritical},
		{Severity: normalizer.SeverityHigh, Suppressed: true},
		{Severity: normalizer.SeverityMedium},
	}
	got := countActiveFindings(findings)
	if got.Total != 2 || got.Critical != 1 || got.Medium != 1 || got.High != 0 {
		t.Errorf("countActiveFindings() = %+v, want total=2 critical=1 medium=1", got)
	}
}

func TestResolveOutputPaths_Local(t *testing.T) {
	os.Unsetenv("GITHUB_ACTIONS")
	os.Unsetenv("OUTPUT_PATH")
	sarif, json := resolveOutputPaths()
	if sarif != localSARIFPath || json != localJSONPath {
		t.Errorf("resolveOutputPaths() = (%q, %q), want local paths", sarif, json)
	}
}

func TestResolveOutputPaths_ActionDefaults(t *testing.T) {
	t.Setenv("OUTPUT_PATH", localSARIFPath)
	t.Setenv("JSON_PATH", localJSONPath)
	sarif, json := resolveOutputPaths()
	if sarif != localSARIFPath || json != localJSONPath {
		t.Errorf("resolveOutputPaths() = (%q, %q), want workspace paths", sarif, json)
	}
}

func TestResolveOutputPaths_OutputPathOnly(t *testing.T) {
	t.Setenv("OUTPUT_PATH", "/custom/out.sarif")
	os.Unsetenv("JSON_PATH")
	_, json := resolveOutputPaths()
	if json != localJSONPath {
		t.Errorf("json path = %q, want default %q", json, localJSONPath)
	}
}
