package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/reporter"
)

// TestBitbucketPipelineE2E exercises the Bitbucket CI path the way run() does:
// ApplyBitbucketScannerDefaults, scan with format=comment,json, PR comment upsert,
// Code Insights upload, and pipeline-check via a fake binary on PATH.
// Live Bitbucket is replaced by httptest + BITBUCKET_API_URL.
func TestBitbucketPipelineE2E(t *testing.T) {
	var mu sync.Mutex
	var commentCreated, reportPut, annotationsPosted bool
	var commentBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pullrequests/") && strings.HasSuffix(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"values":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
			commentCreated = true
			commentBody = string(body)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/reports/muninn"):
			reportPut = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/annotations"):
			annotationsPosted = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	os.Unsetenv("GITHUB_EVENT_NAME")
	t.Setenv("BITBUCKET_COMMIT", "abc123def")
	t.Setenv("BITBUCKET_PIPELINE_UUID", "{uuid}")
	t.Setenv("BITBUCKET_PR_ID", "99")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "bb-token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	fixture, err := os.ReadFile("testdata/pipeline-check/sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	addFakePipelineCheckToPath(t, fixture, 1)

	dir := chdirTemp(t)
	writeBitbucketPipelineStub(t, dir)
	writeMuninnConfigHostScannersOff(t, dir)

	cfg, err := config.Load(filepath.Join(dir, "muninn.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !isBitbucketCI() {
		t.Fatal("isBitbucketCI() = false, want true with BITBUCKET_COMMIT set")
	}
	config.ApplyBitbucketScannerDefaults(cfg)

	if cfg.Scanners["zizmor"].Enabled || cfg.Scanners["actionlint"].Enabled || cfg.Scanners["poutine"].Enabled {
		t.Fatal("GitHub Actions scanners should be disabled on Bitbucket")
	}
	if !cfg.Scanners["pipeline-check"].Enabled {
		t.Fatal("pipeline-check should be enabled on Bitbucket via defaults")
	}

	if err := scan(context.Background(), cfg, dir, "comment,json"); err != nil {
		t.Fatalf("scan() = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !commentCreated {
		t.Error("expected Bitbucket PR comment create")
	}
	if !strings.Contains(commentBody, reporter.CommentMarker) && !strings.Contains(commentBody, "Muninn") {
		t.Errorf("comment body missing Muninn marker/content: %q", commentBody)
	}
	if !reportPut {
		t.Error("expected Code Insights report PUT")
	}
	if !annotationsPosted {
		t.Error("expected Code Insights annotations POST")
	}

	data, err := os.ReadFile(localJSONPath)
	if err != nil {
		t.Fatalf("read muninn.json: %v", err)
	}
	var report struct {
		Findings []normalizer.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode muninn.json: %v", err)
	}
	var pcCount int
	for _, f := range report.Findings {
		if f.Tool == "pipeline-check" {
			pcCount++
		}
	}
	if pcCount == 0 {
		t.Fatalf("expected pipeline-check findings in muninn.json, got %d total findings", len(report.Findings))
	}
}

// TestRun_BitbucketCIPath drives run() so ApplyBitbucketScannerDefaults is
// invoked from production entrypoint code, not only from tests.
func TestRun_BitbucketCIPath(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"values":[]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	os.Unsetenv("GITHUB_EVENT_NAME")
	t.Setenv("BITBUCKET_COMMIT", "deadbeef")
	t.Setenv("BITBUCKET_PR_ID", "7")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	fixture, err := os.ReadFile("testdata/pipeline-check/sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	addFakePipelineCheckToPath(t, fixture, 1)

	dir := chdirTemp(t)
	writeBitbucketPipelineStub(t, dir)
	writeMuninnConfigHostScannersOff(t, dir)
	setArgs(t, "--config", filepath.Join(dir, "muninn.yml"), "--target", dir, "--output", "comment,json", "--fail-on", "critical")

	if code := run(); code != 0 {
		t.Fatalf("run() exit = %d, want 0", code)
	}

	mu.Lock()
	defer mu.Unlock()
	var sawComment, sawReport bool
	for path := range hits {
		if strings.Contains(path, "/comments") && strings.HasPrefix(path, "POST ") {
			sawComment = true
		}
		if strings.Contains(path, "/reports/muninn") && strings.HasPrefix(path, "PUT ") {
			sawReport = true
		}
	}
	if !sawComment {
		t.Errorf("run() did not POST a PR comment; hits=%v", hits)
	}
	if !sawReport {
		t.Errorf("run() did not PUT Code Insights report; hits=%v", hits)
	}

	data, err := os.ReadFile(localJSONPath)
	if err != nil {
		t.Fatalf("read muninn.json: %v", err)
	}
	var report struct {
		Findings []normalizer.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode muninn.json: %v", err)
	}
	var pcCount int
	for _, f := range report.Findings {
		if f.Tool == "pipeline-check" {
			pcCount++
		}
	}
	if pcCount == 0 {
		t.Fatalf("run() should auto-enable pipeline-check; got %d pipeline-check findings (%d total)", pcCount, len(report.Findings))
	}
}

func writeBitbucketPipelineStub(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "bitbucket-pipelines.yml")
	content := "image: node:22\npipelines:\n  default:\n    - step:\n        script:\n          - echo hi\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// addFakePipelineCheckToPath installs a pipeline_check shim that cats fixture
// and exits with exitCode (1 = findings / default gate).
func addFakePipelineCheckToPath(t *testing.T, fixture []byte, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	fixPath := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixPath, fixture, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	bin := filepath.Join(dir, "pipeline_check")
	script := fmt.Sprintf("#!/bin/sh\ncat '%s'\nexit %d\n", fixPath, exitCode)
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake pipeline_check: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// writeMuninnConfigHostScannersOff disables unrelated scanners so tests stay
// fast on developer machines. Platform-defaulted keys (pipeline-check and the
// GitHub Actions scanners) are omitted so ApplyBitbucketScannerDefaults /
// run() apply those defaults automatically.
func writeMuninnConfigHostScannersOff(t *testing.T, dir string) {
	t.Helper()
	content := []byte(`version: 1
fail-on: critical
scanners:
  gitleaks:
    enabled: false
  semgrep:
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
