//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/reporter"
)

// TestBitbucketPipeE2E runs the compiled muninn binary under Bitbucket CI env
// vars, pointing BITBUCKET_API_URL at a fake Cloud API. It does not call the
// real Bitbucket API (that would need credentials and a live workspace).
func TestBitbucketPipeE2E(t *testing.T) {
	var mu sync.Mutex
	var commentBody string
	var sawComment, sawReport, sawAnnotations bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"values":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
			sawComment = true
			commentBody = string(body)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/reports/muninn"):
			sawReport = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/annotations"):
			sawAnnotations = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected Bitbucket API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	workDir := t.TempDir()
	writeIntegrationBitbucketPipeline(t, workDir)
	writeIntegrationMuninnConfig(t, workDir)
	binDir := installFakePipelineCheck(t, filepath.Join(repoRoot, "testdata", "pipeline-check", "sample.json"))

	cmd := exec.Command(muninnBin,
		"--config", filepath.Join(workDir, "muninn.yml"),
		"--target", workDir,
		"--output", "comment,json",
		"--fail-on", "critical",
	)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"BITBUCKET_COMMIT=abc123",
		"BITBUCKET_PIPELINE_UUID={test}",
		"BITBUCKET_PR_ID=42",
		"BITBUCKET_WORKSPACE=acme",
		"BITBUCKET_REPO_SLUG=app",
		"BITBUCKET_ACCESS_TOKEN=test-token",
		"BITBUCKET_API_URL="+srv.URL,
		"GITHUB_EVENT_NAME=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("muninn failed: %v\n%s", err, out)
	}
	log := string(out)
	if !strings.Contains(log, "pipeline-check:") {
		t.Fatalf("expected pipeline-check to run, log:\n%s", log)
	}
	if !strings.Contains(log, "zizmor disabled in config") {
		t.Fatalf("zizmor should be disabled on Bitbucket, log:\n%s", log)
	}

	mu.Lock()
	defer mu.Unlock()
	if !sawComment {
		t.Fatal("expected PR comment POST to fake Bitbucket API")
	}
	if !strings.Contains(commentBody, reporter.CommentMarker) && !strings.Contains(commentBody, "Muninn") {
		t.Errorf("comment payload missing Muninn content: %q", commentBody)
	}
	if !sawReport {
		t.Fatal("expected Code Insights report PUT")
	}
	if !sawAnnotations {
		t.Fatal("expected Code Insights annotations POST")
	}

	data, err := os.ReadFile(filepath.Join(workDir, jsonReportFile))
	if err != nil {
		t.Fatalf("read muninn.json: %v", err)
	}
	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode muninn.json: %v", err)
	}
	if !hasToolFinding(report.Findings, "pipeline-check") {
		t.Fatalf("muninn.json missing pipeline-check findings; tools=%v", findingTools(report.Findings))
	}
}

func writeIntegrationBitbucketPipeline(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "bitbucket-pipelines.yml")
	content := "image: node:22\npipelines:\n  default:\n    - step:\n        script:\n          - echo hi\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func writeIntegrationMuninnConfig(t *testing.T, dir string) {
	t.Helper()
	// Explicit list so ApplyBitbucketScannerDefaults keeps pipeline-check on and
	// host PATH scanners (gitleaks, checkov, …) do not slow or noise the test.
	content := []byte(`version: 1
fail-on: critical
scanners:
  pipeline-check:
    enabled: true
  gitleaks:
    enabled: false
  semgrep:
    enabled: false
  zizmor:
    enabled: false
  actionlint:
    enabled: false
  poutine:
    enabled: false
  trivy:
    enabled: false
  osv-scanner:
    enabled: false
  checkov:
    enabled: false
`)
	if err := os.WriteFile(filepath.Join(dir, "muninn.yml"), content, 0644); err != nil {
		t.Fatalf("WriteFile muninn.yml: %v", err)
	}
}

func installFakePipelineCheck(t *testing.T, fixturePath string) string {
	t.Helper()
	dir := t.TempDir()
	dest := filepath.Join(dir, "fixture.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(dest, data, 0644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	bin := filepath.Join(dir, "pipeline_check")
	script := fmt.Sprintf("#!/bin/sh\ncat '%s'\nexit 1\n", dest)
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake pipeline_check: %v", err)
	}
	return dir
}

func hasToolFinding(findings []normalizer.Finding, tool string) bool {
	for _, f := range findings {
		if f.Tool == tool {
			return true
		}
	}
	return false
}

func findingTools(findings []normalizer.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.Tool] {
			seen[f.Tool] = true
			out = append(out, f.Tool)
		}
	}
	return out
}
