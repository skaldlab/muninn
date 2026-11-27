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

// skillSpectorCollectionDirs are conventional in-repo skill pack locations.
var skillSpectorCollectionDirs = []string{
	".claude/skills",
	".agents/skills",
	".cursor/skills",
	"skills",
}

// skillSpectorReport mirrors `skillspector scan --format json` output.
type skillSpectorReport struct {
	Issues []skillSpectorIssue  `json:"issues"`
	Skills []skillSpectorReport `json:"skills"`
}

// skillSpectorIssue is one finding in a SkillSpector JSON report.
type skillSpectorIssue struct {
	ID          string               `json:"id"`
	FindingID   string               `json:"finding_id"`
	Pattern     string               `json:"pattern"`
	Severity    string               `json:"severity"`
	Location    skillSpectorLocation `json:"location"`
	Finding     string               `json:"finding"`
	Explanation string               `json:"explanation"`
	Remediation string               `json:"remediation"`
	Surface     string               `json:"surface"`
	Category    string               `json:"category"`
	Confidence  float64              `json:"confidence"`
}

// skillSpectorLocation is the file/line where an issue was found.
type skillSpectorLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

// SkillSpector wraps NVIDIA SkillSpector for AI agent skill security scanning.
// See: https://github.com/NVIDIA/SkillSpector
type SkillSpector struct {
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd
	lookPath func(string) (string, error)
}

// NewSkillSpector returns a SkillSpector scanner ready for production use.
func NewSkillSpector() *SkillSpector {
	return &SkillSpector{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (s *SkillSpector) Name() string { return "skillspector" }

// IsAvailable implements Scanner.
func (s *SkillSpector) IsAvailable() bool {
	_, err := s.lookPath("skillspector")
	return err == nil
}

// Configure implements Scanner. SkillSpector has no configurable options.
func (s *SkillSpector) Configure(_ config.ScannerConfig) {}

// Run implements Scanner. Repos without agent skills are a no-op.
func (s *SkillSpector) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("skillspector: binary not found on PATH")
	}
	jobs := skillSpectorScanJobs(target)
	if len(jobs) == 0 {
		return nil, nil
	}
	var all []normalizer.Finding
	for _, job := range jobs {
		findings, err := s.scanJob(ctx, job)
		if err != nil {
			return nil, err
		}
		all = append(all, findings...)
	}
	return all, nil
}

type skillSpectorJob struct {
	path      string
	recursive bool
}

func skillSpectorScanJobs(target string) []skillSpectorJob {
	var jobs []skillSpectorJob
	if skillSpectorHasManifest(target) {
		jobs = append(jobs, skillSpectorJob{path: target, recursive: false})
	}
	for _, rel := range skillSpectorCollectionDirs {
		dir := filepath.Join(target, filepath.FromSlash(rel))
		if !skillSpectorIsCollection(dir) {
			continue
		}
		jobs = append(jobs, skillSpectorJob{path: dir, recursive: true})
	}
	return jobs
}

func skillSpectorHasManifest(dir string) bool {
	for _, name := range []string{"SKILL.md", "skill.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func skillSpectorIsCollection(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && skillSpectorHasManifest(filepath.Join(dir, e.Name())) {
			return true
		}
	}
	return false
}

func (s *SkillSpector) scanJob(ctx context.Context, job skillSpectorJob) ([]normalizer.Finding, error) {
	doc, err := s.execute(ctx, job)
	if err != nil {
		return nil, err
	}
	return normalizeSkillSpector(doc), nil
}

func (s *SkillSpector) execute(ctx context.Context, job skillSpectorJob) (*skillSpectorReport, error) {
	args := []string{"scan", job.path, "--no-llm", "--format", "json"}
	if job.recursive {
		args = append(args, "--recursive")
	}
	cmd := s.execFunc(ctx, "skillspector", args...)
	out, err := cmd.Output()
	if err != nil && !isSkillSpectorFindingsFound(err) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("skillspector: %w", ctx.Err())
		}
		return nil, fmt.Errorf("skillspector: running scanner: %w", err)
	}
	return parseSkillSpectorJSON(out)
}

func parseSkillSpectorJSON(data []byte) (*skillSpectorReport, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("skillspector: empty report on stdout")
	}
	var doc skillSpectorReport
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("skillspector: parsing JSON: %w", err)
	}
	return &doc, nil
}

func normalizeSkillSpector(doc *skillSpectorReport) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	issues := skillSpectorCollectIssues(doc)
	out := make([]normalizer.Finding, 0, len(issues))
	for _, issue := range issues {
		out = append(out, normalizeOneSkillSpector(issue))
	}
	return out
}

func skillSpectorCollectIssues(doc *skillSpectorReport) []skillSpectorIssue {
	out := append([]skillSpectorIssue{}, doc.Issues...)
	for i := range doc.Skills {
		out = append(out, skillSpectorCollectIssues(&doc.Skills[i])...)
	}
	return out
}

func normalizeOneSkillSpector(issue skillSpectorIssue) normalizer.Finding {
	ruleID := issue.FindingID
	if ruleID == "" {
		ruleID = issue.ID
	}
	file := filepath.ToSlash(issue.Location.File)
	title := issue.Pattern
	if title == "" {
		title = ruleID
	}
	desc := skillSpectorDescription(issue)
	fp := skillSpectorFingerprint(file, ruleID, issue.Location.StartLine)
	meta := map[string]any{}
	if issue.Category != "" {
		meta["category"] = issue.Category
	}
	if issue.Surface != "" {
		meta["surface"] = issue.Surface
	}
	if issue.Confidence > 0 {
		meta["confidence"] = issue.Confidence
	}
	f := normalizer.Finding{
		ID:          fp,
		Tool:        "skillspector",
		Severity:    skillSpectorSeverity(issue.Severity),
		Title:       title,
		Description: desc,
		File:        file,
		Line:        issue.Location.StartLine,
		RuleID:      ruleID,
		RuleURL:     "https://github.com/NVIDIA/SkillSpector",
		Fingerprint: fp,
	}
	if len(meta) > 0 {
		f.Metadata = meta
	}
	return f
}

func skillSpectorDescription(issue skillSpectorIssue) string {
	parts := make([]string, 0, 3)
	if issue.Explanation != "" {
		parts = append(parts, issue.Explanation)
	} else if issue.Finding != "" {
		parts = append(parts, issue.Finding)
	}
	if issue.Remediation != "" {
		parts = append(parts, "Remediation: "+issue.Remediation)
	}
	return strings.Join(parts, "\n\n")
}

func skillSpectorSeverity(severity string) normalizer.Severity {
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

func skillSpectorFingerprint(file, ruleID string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("skillspector:%s:%s:%d", file, ruleID, line)))
	return fmt.Sprintf("%x", sum[:8])
}

// isSkillSpectorFindingsFound reports whether err is exit code 1 (findings /
// elevated risk score), which is not a scanner crash.
func isSkillSpectorFindingsFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
