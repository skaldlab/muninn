package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/skaldlab/muninn/internal/reporter"
)

func TestPostBitbucketPRComment_SkipWithoutPR(t *testing.T) {
	os.Unsetenv("BITBUCKET_PR_ID")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "token")
	if err := postBitbucketPRCommentHTTP(context.Background(), "hello", http.DefaultClient); err != nil {
		t.Fatalf("postBitbucketPRCommentHTTP() = %v, want nil", err)
	}
}

func TestPostBitbucketPRComment_MissingToken(t *testing.T) {
	t.Setenv("BITBUCKET_PR_ID", "12")
	t.Setenv("BITBUCKET_WORKSPACE", "ws")
	t.Setenv("BITBUCKET_REPO_SLUG", "repo")
	os.Unsetenv("BITBUCKET_ACCESS_TOKEN")
	if err := postBitbucketPRCommentHTTP(context.Background(), "hello", http.DefaultClient); err != nil {
		t.Fatalf("postBitbucketPRCommentHTTP() = %v, want nil", err)
	}
}

func TestPostBitbucketPRComment_Create(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"values":[]}`))
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

	t.Setenv("BITBUCKET_PR_ID", "42")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "bb-token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	body := reporter.CommentMarker + "\nscan results"
	if err := postBitbucketPRCommentHTTP(context.Background(), body, srv.Client()); err != nil {
		t.Fatalf("postBitbucketPRCommentHTTP() = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 (list then create)", requests)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/repositories/acme/app/pullrequests/42/comments" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer bb-token" {
		t.Errorf("Authorization = %q, want Bearer bb-token", gotAuth)
	}
	if !strings.Contains(gotBody, "scan results") {
		t.Errorf("body = %q, want comment text", gotBody)
	}
}

func TestPostBitbucketPRComment_UpdateByMarker(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			payload := `{"values":[{"id":99,"content":{"raw":"` + reporter.CommentMarker + `\nold"}}]}`
			_, _ = w.Write([]byte(payload))
		case r.Method == http.MethodPut:
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

	t.Setenv("BITBUCKET_PR_ID", "7")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "bb-token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	if err := postBitbucketPRCommentHTTP(context.Background(), "updated", srv.Client()); err != nil {
		t.Fatalf("postBitbucketPRCommentHTTP() = %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/repositories/acme/app/pullrequests/7/comments/99" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, "updated") {
		t.Errorf("body = %q, want updated comment text", gotBody)
	}
}

func TestPostBitbucketPRComment_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_PR_ID", "1")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "token")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	if err := postBitbucketPRCommentHTTP(context.Background(), "hi", srv.Client()); err != nil {
		t.Fatalf("postBitbucketPRCommentHTTP() = %v, want nil (warning only)", err)
	}
}

func TestBitbucketAPIBase(t *testing.T) {
	os.Unsetenv("BITBUCKET_API_URL")
	if got := bitbucketAPIBase(); got != bitbucketAPIDefault {
		t.Errorf("bitbucketAPIBase() = %q, want default", got)
	}
	t.Setenv("BITBUCKET_API_URL", "https://example.test/2.0/")
	if got := bitbucketAPIBase(); got != "https://example.test/2.0" {
		t.Errorf("bitbucketAPIBase() = %q, want trimmed override", got)
	}
}

func TestParseBitbucketPRIdentity_Errors(t *testing.T) {
	os.Unsetenv("BITBUCKET_WORKSPACE")
	os.Unsetenv("BITBUCKET_REPO_SLUG")
	os.Unsetenv("BITBUCKET_PR_ID")
	if _, _, _, err := parseBitbucketPRIdentity(); err == nil {
		t.Fatal("expected error when workspace unset")
	}
	t.Setenv("BITBUCKET_WORKSPACE", "ws")
	if _, _, _, err := parseBitbucketPRIdentity(); err == nil {
		t.Fatal("expected error when repo unset")
	}
	t.Setenv("BITBUCKET_REPO_SLUG", "repo")
	if _, _, _, err := parseBitbucketPRIdentity(); err == nil {
		t.Fatal("expected error when PR id unset")
	}
	t.Setenv("BITBUCKET_PR_ID", "abc")
	if _, _, _, err := parseBitbucketPRIdentity(); err == nil {
		t.Fatal("expected error when PR id is not numeric")
	}
	t.Setenv("BITBUCKET_PR_ID", "12")
	ws, repo, id, err := parseBitbucketPRIdentity()
	if err != nil || ws != "ws" || repo != "repo" || id != "12" {
		t.Fatalf("got (%q,%q,%q,%v)", ws, repo, id, err)
	}
}

func TestPostBitbucketPRComment_BadIdentity(t *testing.T) {
	t.Setenv("BITBUCKET_PR_ID", "1")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "tok")
	os.Unsetenv("BITBUCKET_WORKSPACE")
	os.Unsetenv("BITBUCKET_REPO_SLUG")
	if err := postBitbucketPRCommentHTTP(context.Background(), "x", http.DefaultClient); err != nil {
		t.Fatalf("want nil (warning only), got %v", err)
	}
}

func TestPostBitbucketPRComment_PaginatedListUpdate(t *testing.T) {
	var gotPath string
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			page++
			w.Header().Set("Content-Type", "application/json")
			if page == 1 {
				next := "http://" + r.Host + "/page2"
				_, _ = w.Write([]byte(`{"values":[{"id":1,"content":{"raw":"other"}}],"next":"` + next + `"}`))
				return
			}
			_, _ = w.Write([]byte(`{"values":[{"id":55,"content":{"raw":"` + reporter.CommentMarker + `\nold"}}]}`))
		case r.Method == http.MethodPut:
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("BITBUCKET_PR_ID", "3")
	t.Setenv("BITBUCKET_WORKSPACE", "acme")
	t.Setenv("BITBUCKET_REPO_SLUG", "app")
	t.Setenv("BITBUCKET_ACCESS_TOKEN", "tok")
	t.Setenv("BITBUCKET_API_URL", srv.URL)

	if err := postBitbucketPRCommentHTTP(context.Background(), "new", srv.Client()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if gotPath != "/repositories/acme/app/pullrequests/3/comments/55" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestTruncateAPIError(t *testing.T) {
	if got := truncateAPIError("  short  ", 10); got != "short" {
		t.Errorf("short = %q", got)
	}
	long := strings.Repeat("a", 50)
	got := truncateAPIError(long, 10)
	if got != "aaaaaaaaa…" {
		t.Errorf("truncate = %q, want 9 a's + ellipsis (ellipsis counts toward n)", got)
	}
	if got := truncateAPIError("café-extra", 5); got != "café…" {
		t.Errorf("rune boundary = %q, want café…", got)
	}
	if got := truncateAPIError("x", 1); got != "x" {
		t.Errorf("exact fit = %q", got)
	}
	if got := truncateAPIError("xy", 1); got != "…" {
		t.Errorf("n=1 truncate = %q, want …", got)
	}
}

func TestFindBitbucketCommentID_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	_, err := findBitbucketCommentID(context.Background(), srv.Client(), "tok", srv.URL+"/comments")
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decoding comment list") {
		t.Errorf("error = %v, want decoding comment list", err)
	}
}

func TestFindBitbucketCommentID_ListStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))
	defer srv.Close()

	_, err := findBitbucketCommentID(context.Background(), srv.Client(), "tok", srv.URL+"/comments")
	if err == nil {
		t.Fatal("expected status error")
	}
	if !strings.Contains(err.Error(), "status 403") {
		t.Errorf("error = %v, want status 403", err)
	}
}

func TestBitbucketPRCommentPoster_ShouldPost(t *testing.T) {
	p := &bitbucketPRCommentPoster{client: http.DefaultClient}
	os.Unsetenv("BITBUCKET_PR_ID")
	if p.ShouldPost() {
		t.Fatal("ShouldPost true without PR id")
	}
	t.Setenv("BITBUCKET_PR_ID", "1")
	if !p.ShouldPost() {
		t.Fatal("ShouldPost false with PR id")
	}
}

// A failed later page must never cause a duplicate comment to be created.
func TestUpsertBitbucketPRComment_PaginationFailureDoesNotWrite(t *testing.T) {
	for _, tc := range []struct {
		name, response, want string
		status               int
	}{
		{"status error", "denied", "status 403", http.StatusForbidden},
		{"invalid JSON", "{broken", "decoding comment list", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				if r.Method != http.MethodGet {
					t.Errorf("unexpected write: %s", r.Method)
					w.WriteHeader(500)
					return
				}
				if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Accept") != "application/json" {
					t.Error("missing list request headers")
				}
				if r.URL.Path == "/page2" {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.response)
					return
				}
				_ = json.NewEncoder(w).Encode(bitbucketCommentList{Values: []bitbucketComment{{ID: 8, Content: bitbucketCommentContent{Raw: "unrelated"}}}, Next: "http://" + r.Host + "/page2"})
			}))
			defer srv.Close()
			t.Setenv("BITBUCKET_API_URL", srv.URL)
			err := upsertBitbucketPRComment(context.Background(), srv.Client(), "token", "ws", "repo", "1", "new")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			want := []string{"GET /repositories/ws/repo/pullrequests/1/comments", "GET /page2"}
			if !reflect.DeepEqual(requests, want) {
				t.Errorf("requests = %v, want %v", requests, want)
			}
		})
	}
}

func TestDoBitbucketJSON_StatusAndPayload(t *testing.T) {
	for _, status := range []int{200, 201, 204, 400, 401, 429, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			payload := `{"content":{"raw":"quoted \\\" text\\nnext line"}}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.Method != http.MethodPut || string(body) != payload {
					t.Errorf("request = %s %q", r.Method, body)
				}
				for key, want := range map[string]string{"Authorization": "Bearer token", "Accept": "application/json", "Content-Type": "application/json"} {
					if got := r.Header.Get(key); got != want {
						t.Errorf("%s = %q, want %q", key, got, want)
					}
				}
				w.WriteHeader(status)
				if status >= 400 {
					_, _ = io.WriteString(w, " rejected ")
				}
			}))
			defer srv.Close()
			err := doBitbucketJSON(context.Background(), srv.Client(), http.MethodPut, srv.URL, "token", []byte(payload))
			if status < 300 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), strconv.Itoa(status)) || !strings.Contains(err.Error(), "rejected") {
				t.Errorf("error = %v, want status and response body", err)
			}
		})
	}
}
