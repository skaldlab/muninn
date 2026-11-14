package main

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestBitbucketAnnotationsFromFindings_TruncatesWithinLimits(t *testing.T) {
	// Bitbucket summary/details limits are enforced via truncateAPIError(450/2000).
	title := strings.Repeat("タイトル", 200) // multi-byte runes
	desc := strings.Repeat("詳細", 1200)
	annots := bitbucketAnnotationsFromFindings([]normalizer.Finding{{
		Title: title, Description: desc, Severity: normalizer.SeverityHigh, Fingerprint: "lim",
	}})
	if len(annots) != 1 {
		t.Fatalf("len = %d, want 1", len(annots))
	}
	if n := len([]rune(annots[0].Summary)); n > 450 {
		t.Errorf("Summary rune count = %d, want <= 450", n)
	}
	if n := len([]rune(annots[0].Details)); n > 2000 {
		t.Errorf("Details rune count = %d, want <= 2000", n)
	}
	if !strings.HasSuffix(annots[0].Summary, "…") {
		t.Errorf("Summary should end with ellipsis, got %q", annots[0].Summary[len(annots[0].Summary)-3:])
	}
	if !strings.HasSuffix(annots[0].Details, "…") {
		t.Errorf("Details should end with ellipsis")
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

func TestPostBitbucketAnnotations_BatchBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, 99, 100, 101, 201, 1001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			findings := []normalizer.Finding{{Suppressed: true, Fingerprint: "hidden"}}
			for i := 0; i < count; i++ {
				findings = append(findings, normalizer.Finding{Fingerprint: fmt.Sprint(i), Title: "finding"})
			}
			var batches []int
			var ids []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/repositories/ws/repo/commit/sha/reports/muninn/annotations" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("missing request headers")
				}
				var batch []bitbucketAnnotation
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				batches = append(batches, len(batch))
				for _, a := range batch {
					ids = append(ids, a.ExternalID)
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()
			t.Setenv("BITBUCKET_API_URL", srv.URL)
			if err := postBitbucketAnnotations(context.Background(), srv.Client(), "token", "ws", "repo", "sha", findings); err != nil {
				t.Fatal(err)
			}
			want := min(count, 1000)
			if len(ids) != want {
				t.Fatalf("uploaded %d annotations, want %d", len(ids), want)
			}
			if len(batches) != (want+99)/100 {
				t.Errorf("batches = %v", batches)
			}
			for i, size := range batches {
				if size != min(100, want-i*100) {
					t.Errorf("batch %d size = %d", i, size)
				}
			}
			for i, id := range ids {
				if id != "muninn-"+fmt.Sprint(i) {
					t.Errorf("annotation %d ID = %q", i, id)
				}
			}
		})
	}
}

func TestPostBitbucketAnnotations_StopsAfterFailedBatch(t *testing.T) {
	findings := make([]normalizer.Finding, 201)
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 2 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("BITBUCKET_API_URL", srv.URL)
	err := postBitbucketAnnotations(context.Background(), srv.Client(), "token", "ws", "repo", "sha", findings)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("error = %v, want rate limit error", err)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2", requests)
	}
}

func TestPutBitbucketReport_ThresholdAndSuppression(t *testing.T) {
	for _, tc := range []struct {
		name, failOn, result string
		findings             []normalizer.Finding
		visible              int
	}{
		{name: "below threshold", failOn: "high", result: "PASSED", findings: []normalizer.Finding{{Severity: normalizer.SeverityMedium}}, visible: 1},
		{name: "at threshold", failOn: "high", result: "FAILED", findings: []normalizer.Finding{{Severity: normalizer.SeverityHigh}}, visible: 1},
		{name: "suppressed critical", failOn: "high", result: "PASSED", findings: []normalizer.Finding{{Severity: normalizer.SeverityCritical, Suppressed: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Result  string `json:"result"`
					Details string `json:"details"`
					Data    []struct {
						Value int `json:"value"`
					} `json:"data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if body.Result != tc.result {
					t.Errorf("result = %q, want %q", body.Result, tc.result)
				}
				if len(body.Data) != 1 || body.Data[0].Value != tc.visible {
					t.Errorf("finding count data = %+v, want %d", body.Data, tc.visible)
				}
				wantDetails := fmt.Sprintf("Muninn found %d security finding(s).", tc.visible)
				if tc.visible == 0 {
					wantDetails = "Muninn found no security issues."
				}
				if body.Details != wantDetails {
					t.Errorf("details = %q, want %q", body.Details, wantDetails)
				}
			}))
			defer srv.Close()
			t.Setenv("BITBUCKET_API_URL", srv.URL)
			if err := putBitbucketReport(context.Background(), srv.Client(), "token", "ws", "repo", "sha", tc.findings, tc.failOn); err != nil {
				t.Fatal(err)
			}
		})
	}
}
