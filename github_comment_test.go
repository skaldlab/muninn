package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostPRComment_NotPR(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_TOKEN", "token")
	if err := postPRComment(context.Background(), "hello"); err != nil {
		t.Fatalf("postPRComment() = %v, want nil", err)
	}
}

func TestPostPRComment_MissingToken(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	os.Unsetenv("GITHUB_TOKEN")
	if err := postPRComment(context.Background(), "hello"); err != nil {
		t.Fatalf("postPRComment() = %v, want nil", err)
	}
}

func TestPostPRComment_Success(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
			return
		case r.Method == http.MethodPost:
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			gotBody = string(body)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_REPOSITORY", "skaldlab/muninn")
	t.Setenv("GITHUB_API_URL", srv.URL)
	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":42}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)

	if err := postPRCommentHTTP(context.Background(), "scan results", srv.Client()); err != nil {
		t.Fatalf("postPRCommentHTTP() = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 (list then create)", requests)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/repos/skaldlab/muninn/issues/42/comments" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", gotAuth)
	}
	if !strings.Contains(gotBody, "scan results") {
		t.Errorf("body = %q, want comment text", gotBody)
	}
}

func TestPostPRComment_UpdatesExisting(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":123,"body":"## 🪶 Muninn Security Scan\n\nold results"}]`))
		case r.Method == http.MethodPatch:
			gotMethod = r.Method
			gotPath = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			gotBody = string(body)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_REPOSITORY", "skaldlab/muninn")
	t.Setenv("GITHUB_API_URL", srv.URL)
	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":42}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)

	if err := postPRCommentHTTP(context.Background(), "updated results", srv.Client()); err != nil {
		t.Fatalf("postPRCommentHTTP() = %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
	}
	if gotPath != "/repos/skaldlab/muninn/issues/comments/123" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, "updated results") {
		t.Errorf("body = %q, want updated comment text", gotBody)
	}
}

func TestPostPRCommentHTTP_MissingRepository(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_TOKEN", "token")
	os.Unsetenv("GITHUB_REPOSITORY")
	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":1}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	if err := postPRCommentHTTP(context.Background(), "hi", http.DefaultClient); err != nil {
		t.Fatalf("postPRCommentHTTP() = %v", err)
	}
}

func TestPostPRCommentHTTP_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_TOKEN", "token")
	t.Setenv("GITHUB_REPOSITORY", "skaldlab/muninn")
	t.Setenv("GITHUB_API_URL", srv.URL)
	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":7}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	if err := postPRCommentHTTP(context.Background(), "hi", srv.Client()); err != nil {
		t.Fatalf("postPRCommentHTTP() = %v", err)
	}
}

func TestPullRequestNumber_Success(t *testing.T) {
	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":99}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	got, err := pullRequestNumber()
	if err != nil || got != 99 {
		t.Fatalf("pullRequestNumber() = (%d, %v), want (99, nil)", got, err)
	}
}

func TestPullRequestNumber_Errors(t *testing.T) {
	os.Unsetenv("GITHUB_EVENT_PATH")
	if _, err := pullRequestNumber(); err == nil {
		t.Fatal("expected error when GITHUB_EVENT_PATH unset")
	}

	eventFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(eventFile, []byte(`not json`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	if _, err := pullRequestNumber(); err == nil {
		t.Fatal("expected parse error")
	}

	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{}}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := pullRequestNumber(); err == nil {
		t.Fatal("expected missing number error")
	}
}

func TestApiBaseURL(t *testing.T) {
	os.Unsetenv("GITHUB_API_URL")
	if got := apiBaseURL(); got != "https://api.github.com" {
		t.Errorf("apiBaseURL() = %q, want default API URL", got)
	}
	t.Setenv("GITHUB_API_URL", "https://example.test/api/")
	if got := apiBaseURL(); got != "https://example.test/api" {
		t.Errorf("apiBaseURL() = %q, want trimmed override", got)
	}
}

func TestRenderComment(t *testing.T) {
	body, err := renderComment(context.Background(), nil)
	if err != nil {
		t.Fatalf("renderComment() = %v", err)
	}
	if !strings.Contains(body, "No security issues found") {
		t.Errorf("comment body = %q, want empty-scan message", body)
	}
}
