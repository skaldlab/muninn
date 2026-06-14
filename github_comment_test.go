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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusCreated)
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
