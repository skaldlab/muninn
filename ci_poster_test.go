package main

import (
	"context"
	"net/http"
	"os"
	"testing"
)

func TestSelectPRCommentPoster_GitHub(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	os.Unsetenv("BITBUCKET_PR_ID")
	p := selectPRCommentPoster(http.DefaultClient)
	if p == nil {
		t.Fatal("expected GitHub poster")
	}
	if _, ok := p.(*githubPRCommentPoster); !ok {
		t.Fatalf("got %T, want *githubPRCommentPoster", p)
	}
	if !p.ShouldPost() {
		t.Fatal("ShouldPost() = false, want true")
	}
}

func TestSelectPRCommentPoster_Bitbucket(t *testing.T) {
	os.Unsetenv("GITHUB_EVENT_NAME")
	t.Setenv("BITBUCKET_PR_ID", "9")
	p := selectPRCommentPoster(http.DefaultClient)
	if p == nil {
		t.Fatal("expected Bitbucket poster")
	}
	if _, ok := p.(*bitbucketPRCommentPoster); !ok {
		t.Fatalf("got %T, want *bitbucketPRCommentPoster", p)
	}
}

func TestSelectPRCommentPoster_Neither(t *testing.T) {
	os.Unsetenv("GITHUB_EVENT_NAME")
	os.Unsetenv("BITBUCKET_PR_ID")
	if p := selectPRCommentPoster(http.DefaultClient); p != nil {
		t.Fatalf("got %T, want nil", p)
	}
}

func TestPostPRCommentWithClient_NeitherNoOp(t *testing.T) {
	os.Unsetenv("GITHUB_EVENT_NAME")
	os.Unsetenv("BITBUCKET_PR_ID")
	if err := postPRCommentWithClient(context.Background(), "x", http.DefaultClient); err != nil {
		t.Fatalf("postPRCommentWithClient() = %v", err)
	}
}

func TestSelectPRCommentPoster_GitHubWinsOverBitbucket(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("BITBUCKET_PR_ID", "1")
	p := selectPRCommentPoster(http.DefaultClient)
	if _, ok := p.(*githubPRCommentPoster); !ok {
		t.Fatalf("got %T, want *githubPRCommentPoster when both set", p)
	}
}
