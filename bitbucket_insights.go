package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/skaldlab/muninn/internal/normalizer"
)

const (
	bitbucketReportID    = "muninn"
	bitbucketReportTitle = "Muninn Security Scan"
	bitbucketAnnotBatch  = 100
	bitbucketAnnotMax    = 1000
)

// isBitbucketCI reports whether the process is running inside Bitbucket Pipelines.
func isBitbucketCI() bool {
	return os.Getenv("BITBUCKET_COMMIT") != "" || os.Getenv("BITBUCKET_PIPELINE_UUID") != ""
}

// uploadBitbucketInsights creates or updates a Code Insights report for the
// current commit. Failures are warnings only so the scan exit code is unchanged.
func uploadBitbucketInsights(ctx context.Context, findings []normalizer.Finding, failOn string) error {
	return uploadBitbucketInsightsHTTP(ctx, findings, failOn, http.DefaultClient)
}

func uploadBitbucketInsightsHTTP(ctx context.Context, findings []normalizer.Finding, failOn string, client *http.Client) error {
	if !isBitbucketCI() {
		return nil
	}

	token := os.Getenv("BITBUCKET_ACCESS_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "muninn: warning: BITBUCKET_ACCESS_TOKEN not set, skipping Code Insights")
		return nil
	}

	workspace := os.Getenv("BITBUCKET_WORKSPACE")
	repo := os.Getenv("BITBUCKET_REPO_SLUG")
	commit := os.Getenv("BITBUCKET_COMMIT")
	if workspace == "" || repo == "" || commit == "" {
		fmt.Fprintln(os.Stderr, "muninn: warning: Bitbucket identity incomplete, skipping Code Insights")
		return nil
	}

	if err := putBitbucketReport(ctx, client, token, workspace, repo, commit, findings, failOn); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: failed to upload Code Insights: %v\n", err)
		return nil
	}
	if err := postBitbucketAnnotations(ctx, client, token, workspace, repo, commit, findings); err != nil {
		fmt.Fprintf(os.Stderr, "muninn: warning: failed to upload Code Insights annotations: %v\n", err)
	}
	return nil
}

func putBitbucketReport(ctx context.Context, client *http.Client, token, workspace, repo, commit string, findings []normalizer.Finding, failOn string) error {
	visible := 0
	for _, f := range findings {
		if !f.Suppressed {
			visible++
		}
	}
	result := "PASSED"
	if checkFailOn(failOn, findings) != nil {
		result = "FAILED"
	}
	details := fmt.Sprintf("Muninn found %d security finding(s).", visible)
	if visible == 0 {
		details = "Muninn found no security issues."
	}

	payload, err := json.Marshal(map[string]any{
		"title":       bitbucketReportTitle,
		"details":     details,
		"report_type": "SECURITY",
		"reporter":    "Muninn",
		"result":      result,
		"data": []map[string]any{
			{"title": "Findings", "type": "NUMBER", "value": visible},
		},
	})
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}

	url := fmt.Sprintf("%s/repositories/%s/%s/commit/%s/reports/%s",
		bitbucketAPIBase(), workspace, repo, commit, bitbucketReportID)
	return doBitbucketJSON(ctx, client, http.MethodPut, url, token, payload)
}

type bitbucketAnnotation struct {
	ExternalID     string `json:"external_id"`
	AnnotationType string `json:"annotation_type"`
	Summary        string `json:"summary"`
	Details        string `json:"details,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Path           string `json:"path,omitempty"`
	Line           int    `json:"line,omitempty"`
}

func postBitbucketAnnotations(ctx context.Context, client *http.Client, token, workspace, repo, commit string, findings []normalizer.Finding) error {
	annots := bitbucketAnnotationsFromFindings(findings)
	if len(annots) == 0 {
		return nil
	}
	base := fmt.Sprintf("%s/repositories/%s/%s/commit/%s/reports/%s/annotations",
		bitbucketAPIBase(), workspace, repo, commit, bitbucketReportID)

	for i := 0; i < len(annots); i += bitbucketAnnotBatch {
		end := i + bitbucketAnnotBatch
		if end > len(annots) {
			end = len(annots)
		}
		payload, err := json.Marshal(annots[i:end])
		if err != nil {
			return fmt.Errorf("encoding annotations: %w", err)
		}
		if err := doBitbucketJSON(ctx, client, http.MethodPost, base, token, payload); err != nil {
			return err
		}
	}
	return nil
}

func bitbucketAnnotationsFromFindings(findings []normalizer.Finding) []bitbucketAnnotation {
	out := make([]bitbucketAnnotation, 0, len(findings))
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if len(out) >= bitbucketAnnotMax {
			break
		}
		id := f.Fingerprint
		if id == "" {
			id = f.ID
		}
		if id == "" {
			id = fmt.Sprintf("muninn-%d", len(out)+1)
		}
		a := bitbucketAnnotation{
			ExternalID:     "muninn-" + id,
			AnnotationType: "VULNERABILITY",
			Summary:        truncateAPIError(f.Title, 450),
			Details:        truncateAPIError(f.Description, 2000),
			Severity:       bitbucketAnnotationSeverity(f.Severity),
			Path:           f.File,
			Line:           f.Line,
		}
		out = append(out, a)
	}
	return out
}

func bitbucketAnnotationSeverity(s normalizer.Severity) string {
	switch s {
	case normalizer.SeverityCritical:
		return "CRITICAL"
	case normalizer.SeverityHigh:
		return "HIGH"
	case normalizer.SeverityMedium:
		return "MEDIUM"
	case normalizer.SeverityLow, normalizer.SeverityInfo:
		return "LOW"
	default:
		return "LOW"
	}
}
