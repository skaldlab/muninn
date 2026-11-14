package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// pipelineCheckReport mirrors the JSON document from
// `pipeline_check --output json` (schema_version 1.1).
type pipelineCheckReport struct {
	Findings []pipelineCheckFinding `json:"findings"`
}

// pipelineCheckFinding is one failing check in the JSON report.
type pipelineCheckFinding struct {
	CheckID        string `json:"check_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Resource       string `json:"resource"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Passed         bool   `json:"passed"`
}

// PipelineCheck wraps the pipeline-check Bitbucket Pipelines security scanner.
// See: https://github.com/dmartinochoa/pipeline-check
type PipelineCheck struct {
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd
	lookPath func(string) (string, error)
}

// NewPipelineCheck returns a PipelineCheck scanner ready for production use.
func NewPipelineCheck() *PipelineCheck {
	return &PipelineCheck{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (p *PipelineCheck) Name() string { return "pipeline-check" }

// IsAvailable implements Scanner.
func (p *PipelineCheck) IsAvailable() bool {
	_, err := p.lookPath("pipeline_check")
	return err == nil
}

// Configure implements Scanner. PipelineCheck has no configurable options.
func (p *PipelineCheck) Configure(_ config.ScannerConfig) {}

// Run implements Scanner. Repos without bitbucket-pipelines.yml are a no-op.
func (p *PipelineCheck) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !p.IsAvailable() {
		return nil, fmt.Errorf("pipeline-check: binary not found on PATH")
	}
	pipelineFile := filepath.Join(target, "bitbucket-pipelines.yml")
	if _, err := os.Stat(pipelineFile); os.IsNotExist(err) {
		return nil, nil
	}
	doc, err := p.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizePipelineCheck(doc, target), nil
}

func (p *PipelineCheck) execute(ctx context.Context, target string) (*pipelineCheckReport, error) {
	cmd := p.execFunc(ctx, "pipeline_check",
		"--pipeline", "bitbucket",
		"--bitbucket-path", target,
		"--output", "json",
		"--no-chains",
	)
	out, err := cmd.Output()
	if err != nil && !isPipelineCheckFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("pipeline-check: %w", ctx.Err())
		}
		return nil, fmt.Errorf("pipeline-check: running scanner: %w", err)
	}
	return parsePipelineCheckJSON(out)
}

func parsePipelineCheckJSON(data []byte) (*pipelineCheckReport, error) {
	if len(data) == 0 {
		return &pipelineCheckReport{}, nil
	}
	var doc pipelineCheckReport
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("pipeline-check: parsing JSON: %w", err)
	}
	return &doc, nil
}

func normalizePipelineCheck(doc *pipelineCheckReport, target string) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	out := make([]normalizer.Finding, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		if f.Passed {
			continue
		}
		out = append(out, normalizeOnePipelineCheck(f, target))
	}
	return out
}

func normalizeOnePipelineCheck(f pipelineCheckFinding, target string) normalizer.Finding {
	file := pipelineCheckRelPath(f.Resource, target)
	desc := f.Description
	if f.Recommendation != "" {
		desc = f.Description + "\n\nRecommendation: " + f.Recommendation
	}
	fp := pipelineCheckFingerprint(file, f.CheckID)
	return normalizer.Finding{
		ID:          fp,
		Tool:        "pipeline-check",
		Severity:    pipelineCheckSeverity(f.Severity),
		Title:       f.Title,
		Description: desc,
		File:        file,
		Line:        0,
		RuleID:      f.CheckID,
		RuleURL:     "https://dmartinochoa.github.io/pipeline-check/providers/bitbucket/",
		Fingerprint: fp,
	}
}

func pipelineCheckRelPath(resource, target string) string {
	resource = filepath.Clean(resource)
	if target != "" {
		if rel, err := filepath.Rel(filepath.Clean(target), resource); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	if base := filepath.Base(resource); base == "bitbucket-pipelines.yml" {
		return base
	}
	return filepath.ToSlash(resource)
}

func pipelineCheckSeverity(severity string) normalizer.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return normalizer.SeverityCritical
	case "HIGH":
		return normalizer.SeverityHigh
	case "MEDIUM":
		return normalizer.SeverityMedium
	case "LOW":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}

func pipelineCheckFingerprint(file, checkID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("pipeline-check:%s:%s", file, checkID)))
	return fmt.Sprintf("%x", sum[:8])
}

// isPipelineCheckFindingsFound reports whether err is exit code 1 from the
// default CI gate (findings present), which is not a scanner crash.
func isPipelineCheckFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
