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

// pullRequestEvent holds the fields Muninn reads from GITHUB_EVENT_PATH.
type pullRequestEvent struct {
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
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
	if err := createIssueComment(ctx, client, apiBaseURL(), repo, token, number, comment); err != nil {
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

// createIssueComment POSTs a comment body to the GitHub issues comments API.
func createIssueComment(ctx context.Context, client *http.Client, apiBase, repo, token string, number int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments", apiBase, repo, number)
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("encoding comment body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

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
