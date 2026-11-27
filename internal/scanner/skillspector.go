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
	Skill  *skillSpectorMeta    `json:"skill"`
	Issues []skillSpectorIssue  `json:"issues"`
	Skills []skillSpectorReport `json:"skills"`
}

// skillSpectorMeta is the skill identity block on a JSON report.
type skillSpectorMeta struct {
	Name   string `json:"name"`
	Source string `json:"source"`
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

// Run implements Scanner. Repos without agent skills are a no-op. When a later
// job fails, findings from completed jobs are still returned with the error.
func (s *SkillSpector) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("skillspector: binary not found on PATH")
	}
	jobs, err := skillSpectorScanJobs(target)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, nil
	}
	var all []normalizer.Finding
	for _, job := range jobs {
		findings, jobErr := s.scanJob(ctx, target, job)
		all = append(all, findings...)
		if jobErr != nil {
			return all, jobErr
		}
	}
	return all, nil
}

type skillSpectorJob struct {
	path      string
	recursive bool
}

func skillSpectorScanJobs(target string) ([]skillSpectorJob, error) {
	var jobs []skillSpectorJob
	hasRoot, err := skillSpectorHasManifest(target)
	if err != nil {
		return nil, err
	}
	if hasRoot {
		jobs = append(jobs, skillSpectorJob{path: target, recursive: false})
	}
	for _, rel := range skillSpectorCollectionDirs {
		dir := filepath.Join(target, filepath.FromSlash(rel))
		ok, err := skillSpectorIsCollection(dir)
		if err != nil {
			return nil, err
		}
		if ok {
			jobs = append(jobs, skillSpectorJob{path: dir, recursive: true})
		}
	}
	return jobs, nil
}

func skillSpectorHasManifest(dir string) (bool, error) {
	for _, name := range []string{"SKILL.md", "skill.md"} {
		path := filepath.Join(dir, name)
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("skillspector: checking %s: %w", path, err)
		}
	}
	return false, nil
}

func skillSpectorIsCollection(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("skillspector: reading %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ok, err := skillSpectorHasManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (s *SkillSpector) scanJob(ctx context.Context, target string, job skillSpectorJob) ([]normalizer.Finding, error) {
	doc, err := s.execute(ctx, job)
	if err != nil {
		return nil, err
	}
	return normalizeSkillSpector(doc, target, job.path), nil
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

func normalizeSkillSpector(doc *skillSpectorReport, target, jobPath string) []normalizer.Finding {
	return normalizeSkillSpectorNode(doc, target, jobPath, jobPath)
}

func normalizeSkillSpectorNode(doc *skillSpectorReport, target, jobPath, skillDir string) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	base := skillDir
	if doc.Skill != nil && doc.Skill.Source != "" {
		base = skillSpectorResolveSource(target, jobPath, doc.Skill.Source)
	}
	out := make([]normalizer.Finding, 0, len(doc.Issues))
	for _, issue := range doc.Issues {
		out = append(out, normalizeOneSkillSpector(issue, target, base))
	}
	for i := range doc.Skills {
		out = append(out, normalizeSkillSpectorNode(&doc.Skills[i], target, jobPath, base)...)
	}
	return out
}

func skillSpectorResolveSource(target, jobPath, source string) string {
	source = filepath.Clean(filepath.FromSlash(source))
	if filepath.IsAbs(source) {
		return source
	}
	source = strings.TrimPrefix(source, "."+string(filepath.Separator))
	if strings.ContainsRune(source, filepath.Separator) {
		return filepath.Join(target, source)
	}
	return filepath.Join(jobPath, source)
}

func skillSpectorRelFile(target, base, file string) string {
	file = filepath.Clean(filepath.FromSlash(file))
	if file == "." || file == "" {
		return ""
	}
	abs := file
	if !filepath.IsAbs(file) {
		abs = filepath.Join(base, file)
	}
	rel, err := filepath.Rel(filepath.Clean(target), abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}

func normalizeOneSkillSpector(issue skillSpectorIssue, target, base string) normalizer.Finding {
	ruleID := issue.FindingID
	if ruleID == "" {
		ruleID = issue.ID
	}
	file := skillSpectorRelFile(target, base, issue.Location.File)
	title := issue.Pattern
	if title == "" {
		title = ruleID
	}
	fp := skillSpectorFingerprint(file, ruleID, issue.Location.StartLine)
	f := normalizer.Finding{
		ID:          fp,
		Tool:        "skillspector",
		Severity:    skillSpectorSeverity(issue.Severity),
		Title:       title,
		Description: skillSpectorDescription(issue),
		File:        file,
		Line:        issue.Location.StartLine,
		RuleID:      ruleID,
		RuleURL:     "https://github.com/NVIDIA/SkillSpector",
		Fingerprint: fp,
		Metadata:    skillSpectorMetadata(issue),
	}
	return f
}

func skillSpectorMetadata(issue skillSpectorIssue) map[string]any {
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
	if len(meta) == 0 {
		return nil
	}
	return meta
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
