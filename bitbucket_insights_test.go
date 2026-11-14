package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

func TestUploadBitbucketInsights_SkipWithoutCI(t *testing.T) {
	os.Unsetenv("BITBUCKET_COMMIT")
	os.Unsetenv("BITBUCKET_PIPELINE_UUID")
	if err := uploadBitbucketInsightsHTTP(context.Background(), nil, "high", http.DefaultClient); err != nil {
		t.Fatalf("uploadBitbucketInsightsHTTP() = %v, want nil", err)
	}
}

func TestUploadBitbucketInsights_MissingToken(t *testing.T) {
	t.Setenv("BITBUCKET_COMMIT", "abc123")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	os.Unsetenv("BITBUCKET_ACCESS_TOKEN")
	if err := uploadBitbucketInsightsHTTP(context.Background(), nil, "high", http.DefaultClient); err != nil {
		t.Fatalf("uploadBitbucketInsightsHTTP() = %v, want nil", err)
	}
}

func TestUploadBitbucketInsights_ReportAndAnnotations(t *testing.T) {
	var reportBody, annotBody string
	var putPath, postPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/reports/muninn"):
			putPath = r.URL.Path
			reportBody = string(body)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/annotations"):
			postPath = r.URL.Path
			annotBody = string(body)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_COMMIT", "deadbeef")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "bb-token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	findings := []normalizer.Finding{
		{
			ID:          "f1",
			Fingerprint: "fp1",
			Title:       "Hardcoded secret",
			Description: "API key in source",
			Severity:    normalizer.SeverityHigh,
			File:        "src/main.go",
			Line:        10,
		},
		{
			ID:         "f2",
			Title:      "suppressed",
			Severity:   normalizer.SeverityCritical,
			Suppressed: true,
			File:       "skip.go",
			Line:       1,
		},
	}

	if err := uploadBitbucketInsightsHTTP(context.Background(), findings, "high", srv.Client()); err != nil {
		t.Fatalf("uploadBitbucketInsightsHTTP() = %v", err)
	}

	wantReportPath := "/repositories/acme/app/commit/deadbeef/reports/muninn"
	if putPath != wantReportPath {
		t.Errorf("report path = %q, want %q", putPath, wantReportPath)
	}
	if !strings.Contains(reportBody, `"result":"FAILED"`) {
		t.Errorf("report body = %q, want FAILED result", reportBody)
	}
	if !strings.Contains(reportBody, `"report_type":"SECURITY"`) {
		t.Errorf("report body = %q, want SECURITY type", reportBody)
	}

	wantAnnotPath := wantReportPath + "/annotations"
	if postPath != wantAnnotPath {
		t.Errorf("annotations path = %q, want %q", postPath, wantAnnotPath)
	}

	var annots []bitbucketAnnotation
	if err := json.Unmarshal([]byte(annotBody), &annots); err != nil {
		t.Fatalf("decode annotations: %v", err)
	}
	if len(annots) != 1 {
		t.Fatalf("annotations = %d, want 1 (suppressed excluded)", len(annots))
	}
	if annots[0].Path != "src/main.go" || annots[0].Line != 10 {
		t.Errorf("annotation location = %s:%d", annots[0].Path, annots[0].Line)
	}
	if annots[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", annots[0].Severity)
	}
	if annots[0].ExternalID != "muninn-fp1" {
		t.Errorf("external_id = %q, want muninn-fp1", annots[0].ExternalID)
	}
}

func TestUploadBitbucketInsights_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_COMMIT", "abc")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	if err := uploadBitbucketInsightsHTTP(context.Background(), nil, "info", srv.Client()); err != nil {
		t.Fatalf("uploadBitbucketInsightsHTTP() = %v, want nil (warning only)", err)
	}
}

func TestBitbucketAnnotationSeverity(t *testing.T) {
	cases := map[normalizer.Severity]string{
		normalizer.SeverityCritical: "CRITICAL",
		normalizer.SeverityHigh:     "HIGH",
		normalizer.SeverityMedium:   "MEDIUM",
		normalizer.SeverityLow:      "LOW",
		normalizer.SeverityInfo:     "LOW",
		normalizer.Severity(""):     "LOW",
	}
	for in, want := range cases {
		if got := bitbucketAnnotationSeverity(in); got != want {
			t.Errorf("bitbucketAnnotationSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUploadBitbucketInsights_IncompleteIdentity(t *testing.T) {
	t.Setenv("BITBUCKET_COMMIT", "abc")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "tok")
	os.Unsetenv("BITBUCKET_WORKSPACE")
	os.Unsetenv("BITBUCKET_REPO_SLUG")
	if err := uploadBitbucketInsightsHTTP(context.Background(), nil, "high", http.DefaultClient); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestUploadBitbucketInsights_ZeroFindingsPassed(t *testing.T) {
	var reportBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			reportBody = string(body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_COMMIT", "abc")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "tok")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	if err := uploadBitbucketInsightsHTTP(context.Background(), nil, "high", srv.Client()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(reportBody, `"result":"PASSED"`) {
		t.Errorf("report = %q, want PASSED", reportBody)
	}
	if !strings.Contains(reportBody, "no security issues") {
		t.Errorf("report = %q, want empty-scan details", reportBody)
	}
}

func TestBitbucketAnnotationsFromFindings_IDFallback(t *testing.T) {
	annots := bitbucketAnnotationsFromFindings([]normalizer.Finding{
		{Title: "x", Severity: normalizer.SeverityLow, ID: "id-only"},
		{Title: "y", Severity: normalizer.SeverityInfo}, // no id/fingerprint
		{Title: "z", Severity: normalizer.SeverityHigh, Suppressed: true},
	})
	if len(annots) != 2 {
		t.Fatalf("len = %d, want 2", len(annots))
	}
	if annots[0].ExternalID != "muninn-id-only" {
		t.Errorf("external_id = %q", annots[0].ExternalID)
	}
	if annots[1].ExternalID != "muninn-muninn-2" {
		t.Errorf("external_id = %q, want muninn-muninn-2", annots[1].ExternalID)
	}
}

func TestBitbucketAnnotationsFromFindings_CapsAtMax(t *testing.T) {
	findings := make([]normalizer.Finding, bitbucketAnnotMax+5)
	for i := range findings {
		findings[i] = normalizer.Finding{Title: "t", Severity: normalizer.SeverityLow, Fingerprint: "fp"}
	}
	annots := bitbucketAnnotationsFromFindings(findings)
	if len(annots) != bitbucketAnnotMax {
		t.Fatalf("len = %d, want %d", len(annots), bitbucketAnnotMax)
	}
}

func TestUploadBitbucketInsights_AnnotationAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("annot fail"))
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_COMMIT", "abc")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "tok")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	findings := []normalizer.Finding{{
		Title: "t", Severity: normalizer.SeverityHigh, File: "a.go", Line: 1, Fingerprint: "fp",
	}}
	if err := uploadBitbucketInsightsHTTP(context.Background(), findings, "info", srv.Client()); err != nil {
		t.Fatalf("want nil (warning only), got %v", err)
	}
}
