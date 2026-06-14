package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/reporter"
)

const muninnCommentLegacyHeader = "Muninn Security Scan"

// pullRequestEvent holds the fields Muninn reads from GITHUB_EVENT_PATH.
type pullRequestEvent struct {
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
}

type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// renderComment formats findings as Markdown for a GitHub PR comment.
func renderComment(ctx context.Context, findings []normalizer.Finding) (string, error) {
	var buf bytes.Buffer
	rep := &reporter.Comment{}
	if err := rep.Write(ctx, &buf, findings); err != nil {
		return "", fmt.Errorf("rendering PR comment: %w", err)
	}
	return buf.String(), nil
}

// postPRComment posts comment on the current pull request when running inside
// GitHub Actions. Non-PR contexts and missing tokens are skipped without error.
func postPRComment(ctx context.Context, comment string) error {
	return postPRCommentHTTP(ctx, comment, http.DefaultClient)
}

// postPRCommentHTTP posts a PR comment using the provided HTTP client.
// API failures are logged as warnings and do not fail the scan.
func postPRCommentHTTP(ctx context.Context, comment string, client *http.Client) error {
	if os.Getenv("GITHUB_EVENT_NAME") != "pull_request" {
		return nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "muninn: warning: GITHUB_TOKEN not set, skipping PR comment")
		return nil
	}
	number, err := pullRequestNumber()
	if err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: %v\n", err)
		return nil
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		fmt.Fprintln(os.Stderr, "muninn: warning: GITHUB_REPOSITORY not set, skipping PR comment")
		return nil
	}
	if err := upsertIssueComment(ctx, client, apiBaseURL(), repo, token, number, comment); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: failed to post PR comment: %v\n", err)
	}
	return nil
}

// apiBaseURL returns the GitHub API root, overridable in tests via GITHUB_API_URL.
func apiBaseURL() string {
	if base := os.Getenv("GITHUB_API_URL"); base != "" {
		return strings.TrimRight(base, "/")
	}
	return "https://api.github.com"
}

// pullRequestNumber reads the PR number from GITHUB_EVENT_PATH.
func pullRequestNumber() (int, error) {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return 0, fmt.Errorf("GITHUB_EVENT_PATH not set, skipping PR comment")
	}
	data, err := os.ReadFile(eventPath)
	if err != nil {
		return 0, fmt.Errorf("reading event payload: %w", err)
	}
	var event pullRequestEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, fmt.Errorf("parsing event payload: %w", err)
	}
	if event.PullRequest.Number == 0 {
		return 0, fmt.Errorf("pull_request.number missing in event payload")
	}
	return event.PullRequest.Number, nil
}

// upsertIssueComment updates an existing Muninn PR comment or creates a new one.
func upsertIssueComment(ctx context.Context, client *http.Client, apiBase, repo, token string, number int, body string) error {
	comments, err := listIssueComments(ctx, client, apiBase, repo, token, number)
	if err != nil {
		return err
	}
	for _, c := range comments {
		if isMuninnComment(c.Body) {
			return updateIssueComment(ctx, client, apiBase, repo, token, c.ID, body)
		}
	}
	return createIssueComment(ctx, client, apiBase, repo, token, number, body)
}

func isMuninnComment(body string) bool {
	return strings.Contains(body, reporter.CommentMarker) ||
		strings.Contains(body, muninnCommentLegacyHeader)
}

func listIssueComments(ctx context.Context, client *http.Client, apiBase, repo, token string, number int) ([]issueComment, error) {
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100", apiBase, repo, number)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building list comments request: %w", err)
	}
	setGitHubHeaders(req, token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing comments: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var comments []issueComment
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return nil, fmt.Errorf("decoding comments: %w", err)
	}
	return comments, nil
}

func updateIssueComment(ctx context.Context, client *http.Client, apiBase, repo, token string, id int64, body string) error {
	url := fmt.Sprintf("%s/repos/%s/issues/comments/%d", apiBase, repo, id)
	return sendIssueComment(ctx, client, http.MethodPatch, url, token, body)
}

// createIssueComment POSTs a comment body to the GitHub issues comments API.
func createIssueComment(ctx context.Context, client *http.Client, apiBase, repo, token string, number int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments", apiBase, repo, number)
	return sendIssueComment(ctx, client, http.MethodPost, url, token, body)
}

func sendIssueComment(ctx context.Context, client *http.Client, method, url, token, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("encoding comment body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	setGitHubHeaders(req, token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GitHub API status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
}
