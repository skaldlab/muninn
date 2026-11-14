package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/skaldlab/muninn/internal/reporter"
)

const bitbucketAPIDefault = "https://api.bitbucket.org/2.0"

// bitbucketPRCommentPoster upserts Muninn's summary via Bitbucket Cloud REST 2.0.
type bitbucketPRCommentPoster struct {
	client *http.Client
}

// ShouldPost reports whether this run is a Bitbucket Pipelines pull request.
func (p *bitbucketPRCommentPoster) ShouldPost() bool {
	return os.Getenv("BITBUCKET_PR_ID") != ""
}

// Upsert creates or updates the Muninn PR comment on Bitbucket Cloud.
func (p *bitbucketPRCommentPoster) Upsert(ctx context.Context, body string) error {
	return postBitbucketPRCommentHTTP(ctx, body, p.client)
}

// postBitbucketPRCommentHTTP posts or updates the Muninn summary on a
// Bitbucket Cloud pull request. Missing PR identity or token yields a warning
// and a nil error so the scan itself never fails on comment delivery.
func postBitbucketPRCommentHTTP(ctx context.Context, comment string, client *http.Client) error {
	if os.Getenv("BITBUCKET_PR_ID") == "" {
		return nil
	}

	token := os.Getenv("BITBUCKET_ACCESS_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "muninn: warning: BITBUCKET_ACCESS_TOKEN not set, skipping PR comment")
		return nil
	}

	workspace, repo, prID, err := parseBitbucketPRIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: %v\n", err)
		return nil
	}

	if err := upsertBitbucketPRComment(ctx, client, token, workspace, repo, prID, comment); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: failed to post Bitbucket PR comment: %v\n", err)
	}
	return nil
}

func parseBitbucketPRIdentity() (workspace, repo, prID string, err error) {
	workspace = os.Getenv("BITBUCKET_WORKSPACE")
	if workspace == "" {
		return "", "", "", fmt.Errorf("BITBUCKET_WORKSPACE is not set")
	}
	repo = os.Getenv("BITBUCKET_REPO_SLUG")
	if repo == "" {
		return "", "", "", fmt.Errorf("BITBUCKET_REPO_SLUG is not set")
	}
	prID = os.Getenv("BITBUCKET_PR_ID")
	if prID == "" {
		return "", "", "", fmt.Errorf("BITBUCKET_PR_ID is not set")
	}
	if _, err := strconv.Atoi(prID); err != nil {
		return "", "", "", fmt.Errorf("BITBUCKET_PR_ID %q is not a number", prID)
	}
	return workspace, repo, prID, nil
}

func bitbucketAPIBase() string {
	if base := strings.TrimRight(os.Getenv("BITBUCKET_API_URL"), "/"); base != "" {
		return base
	}
	return bitbucketAPIDefault
}

type bitbucketCommentContent struct {
	Raw string `json:"raw"`
}

type bitbucketComment struct {
	ID      int64                   `json:"id"`
	Content bitbucketCommentContent `json:"content"`
}

type bitbucketCommentList struct {
	Values []bitbucketComment `json:"values"`
	Next   string             `json:"next"`
}

func upsertBitbucketPRComment(ctx context.Context, client *http.Client, token, workspace, repo, prID, body string) error {
	listURL := fmt.Sprintf("%s/repositories/%s/%s/pullrequests/%s/comments?pagelen=100",
		bitbucketAPIBase(), workspace, repo, prID)

	existingID, err := findBitbucketCommentID(ctx, client, token, listURL)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"content": map[string]string{"raw": body},
	})
	if err != nil {
		return fmt.Errorf("encoding comment: %w", err)
	}

	if existingID != 0 {
		updateURL := fmt.Sprintf("%s/repositories/%s/%s/pullrequests/%s/comments/%d",
			bitbucketAPIBase(), workspace, repo, prID, existingID)
		return doBitbucketJSON(ctx, client, http.MethodPut, updateURL, token, payload)
	}

	createURL := fmt.Sprintf("%s/repositories/%s/%s/pullrequests/%s/comments",
		bitbucketAPIBase(), workspace, repo, prID)
	return doBitbucketJSON(ctx, client, http.MethodPost, createURL, token, payload)
}

func findBitbucketCommentID(ctx context.Context, client *http.Client, token, listURL string) (int64, error) {
	url := listURL
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, fmt.Errorf("creating list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("listing PR comments: %w", err)
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return 0, fmt.Errorf("reading comment list: %w", readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return 0, fmt.Errorf("listing PR comments: status %d: %s", resp.StatusCode, truncateAPIError(string(data), 200))
		}

		var page bitbucketCommentList
		if err := json.Unmarshal(data, &page); err != nil {
			return 0, fmt.Errorf("decoding comment list: %w", err)
		}
		for _, c := range page.Values {
			if strings.Contains(c.Content.Raw, reporter.CommentMarker) {
				return c.ID, nil
			}
		}
		url = page.Next
	}
	return 0, nil
}

func doBitbucketJSON(ctx context.Context, client *http.Client, method, url, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating %s request: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("Bitbucket API status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func truncateAPIError(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	// Ellipsis counts toward n so callers can enforce hard API limits.
	return string(runes[:n-1]) + "…"
}
