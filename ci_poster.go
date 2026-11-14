package main

import (
	"context"
	"net/http"
	"os"
)

// prCommentPoster upserts a Markdown PR comment on a CI host.
type prCommentPoster interface {
	ShouldPost() bool
	Upsert(ctx context.Context, body string) error
}

// selectPRCommentPoster picks the CI provider for PR comments.
// GitHub wins when GITHUB_EVENT_NAME=pull_request; otherwise Bitbucket when
// BITBUCKET_PR_ID is set. Returns nil when neither applies.
func selectPRCommentPoster(client *http.Client) prCommentPoster {
	if os.Getenv("GITHUB_EVENT_NAME") == "pull_request" {
		return &githubPRCommentPoster{client: client}
	}
	if os.Getenv("BITBUCKET_PR_ID") != "" {
		return &bitbucketPRCommentPoster{client: client}
	}
	return nil
}

// postPRComment posts (or updates) the Muninn summary on the current PR.
func postPRComment(ctx context.Context, comment string) error {
	return postPRCommentWithClient(ctx, comment, http.DefaultClient)
}

func postPRCommentWithClient(ctx context.Context, comment string, client *http.Client) error {
	poster := selectPRCommentPoster(client)
	if poster == nil || !poster.ShouldPost() {
		return nil
	}
	return poster.Upsert(ctx, comment)
}
