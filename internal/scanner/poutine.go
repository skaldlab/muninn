package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// poutineOutput mirrors the JSON document poutine v1.x writes to stdout.
type poutineOutput struct {
	Findings []poutineFinding         `json:"findings"`
	Rules    map[string]poutineRule   `json:"rules"`
	BlobSHAs map[string][]poutineRepo `json:"blobshas"`
}

// poutineRule holds rule metadata keyed in the top-level rules map.
type poutineRule struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Level       string `json:"level"`
}

// poutineFinding mirrors one entry in poutine's findings array (v1.x schema).
type poutineFinding struct {
	RuleID string      `json:"rule_id"`
	Purl   string      `json:"purl"`
	Meta   poutineMeta `json:"meta"`
	// Legacy pre-v1 JSON fields; kept so older fixture/output shapes still parse.
	Rule struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	} `json:"rule"`
	Occurrence struct {
		File        string `json:"file"`
		StartLine   int    `json:"startLine"`
		StartColumn int    `json:"startColumn"`
	} `json:"occurrence"`
	Fingerprint string `json:"fingerprint"`
}

// poutineMeta holds per-occurrence location and detail from poutine v1.x.
type poutineMeta struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Job     string `json:"job"`
	Step    string `json:"step"`
	Details string `json:"details"`
	BlobSHA string `json:"blobsha"`
}

// poutineRepo maps a workflow blob SHA back to on-disk paths (analyze_local output).
type poutineRepo struct {
	BranchInfos []poutineBranchInfo `json:"branch_infos"`
}

type poutineBranchInfo struct {
	FilePath []string `json:"file_path"`
}

// Poutine wraps the poutine supply-chain pipeline risk scanner.
// See: https://github.com/boostsecurityio/poutine
type Poutine struct {
	execFunc func(ctx context.Context, name string, args ...string) *exec.Cmd
	lookPath func(string) (string, error)
}

// NewPoutine returns a Poutine scanner ready for production use.
func NewPoutine() *Poutine {
	return &Poutine{
		execFunc: exec.CommandContext,
		lookPath: exec.LookPath,
	}
}

// Name implements Scanner.
func (p *Poutine) Name() string { return "poutine" }

// IsAvailable implements Scanner.
func (p *Poutine) IsAvailable() bool {
	_, err := p.lookPath("poutine")
	return err == nil
}

// Configure implements Scanner. Poutine has no configurable options.
func (p *Poutine) Configure(_ config.ScannerConfig) {}

// Run implements Scanner.
func (p *Poutine) Run(ctx context.Context, target string) ([]normalizer.Finding, error) {
	if !p.IsAvailable() {
		return nil, fmt.Errorf("poutine: binary not found on PATH")
	}
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return nil, nil
	}
	doc, err := p.execute(ctx, target)
	if err != nil {
		return nil, err
	}
	return normalizePoutine(doc), nil
}

func (p *Poutine) execute(ctx context.Context, target string) (*poutineOutput, error) {
	cmd := p.execFunc(ctx, "poutine", "analyze_local", target, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("poutine: %w", ctx.Err())
		}
		return nil, fmt.Errorf("poutine: running scanner: %w", err)
	}
	return parsePoutineJSON(out)
}

func parsePoutineJSON(data []byte) (*poutineOutput, error) {
	if len(data) == 0 {
		return &poutineOutput{}, nil
	}
	var doc poutineOutput
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("poutine: parsing JSON: %w", err)
	}
	return &doc, nil
}

func normalizePoutine(doc *poutineOutput) []normalizer.Finding {
	if doc == nil {
		return nil
	}
	out := make([]normalizer.Finding, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		if finding, ok := normalizeOnePoutine(f, doc.Rules, doc.BlobSHAs); ok {
			out = append(out, finding)
		}
	}
	return out
}

func normalizeOnePoutine(
	f poutineFinding,
	rules map[string]poutineRule,
	blobshas map[string][]poutineRepo,
) (normalizer.Finding, bool) {
	if f.RuleID != "" {
		return normalizeModernPoutine(f, rules, blobshas)
	}
	if f.Rule.ID != "" {
		return normalizeLegacyPoutine(f), true
	}
	return normalizer.Finding{}, false
}

func normalizeModernPoutine(
	f poutineFinding,
	rules map[string]poutineRule,
	blobshas map[string][]poutineRepo,
) (normalizer.Finding, bool) {
	rule := rules[f.RuleID]
	if rule.ID == "" {
		rule.ID = f.RuleID
	}
	if rule.ID == "" {
		return normalizer.Finding{}, false
	}
	file := poutineFile(f.Meta, blobshas)
	desc := f.Meta.Details
	if desc == "" {
		desc = rule.Description
	}
	fp := poutineFingerprint(file, f.Meta.Line, f.Meta.Job, f.Meta.Step, rule.ID)
	return normalizer.Finding{
		ID:          fp,
		Tool:        "poutine",
		Severity:    poutineSeverity(rule.Level),
		Title:       rule.Title,
		Description: desc,
		File:        file,
		Line:        f.Meta.Line,
		RuleID:      rule.ID,
		RuleURL:     poutineRuleURL(rule.ID),
		Fingerprint: fp,
	}, true
}

func normalizeLegacyPoutine(f poutineFinding) normalizer.Finding {
	fp := f.Fingerprint
	if fp == "" {
		fp = poutineFingerprint(f.Occurrence.File, f.Occurrence.StartLine, "", "", f.Rule.ID)
	}
	desc := f.Rule.Description
	return normalizer.Finding{
		ID:          fp,
		Tool:        "poutine",
		Severity:    poutineSeverity(f.Rule.Severity),
		Title:       f.Rule.Title,
		Description: desc,
		File:        f.Occurrence.File,
		Line:        f.Occurrence.StartLine,
		Column:      f.Occurrence.StartColumn,
		RuleID:      f.Rule.ID,
		RuleURL:     poutineRuleURL(f.Rule.ID),
		Fingerprint: fp,
	}
}

func poutineFile(meta poutineMeta, blobshas map[string][]poutineRepo) string {
	if meta.Path != "" {
		return meta.Path
	}
	if meta.BlobSHA == "" {
		return ""
	}
	for _, repo := range blobshas[meta.BlobSHA] {
		for _, branch := range repo.BranchInfos {
			if len(branch.FilePath) > 0 {
				return branch.FilePath[0]
			}
		}
	}
	return ""
}

func poutineRuleURL(ruleID string) string {
	return "https://github.com/boostsecurityio/poutine/blob/main/docs/rules/" + ruleID + ".md"
}

// poutineSeverity maps poutine rule levels (error/warning/note) and legacy
// severity strings (critical/high/medium/low) to Muninn severities.
func poutineSeverity(level string) normalizer.Severity {
	switch level {
	case "critical", "error":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium", "warning":
		return normalizer.SeverityMedium
	case "low":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}

func poutineFingerprint(file string, line int, job, step, ruleID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("poutine:%s:%d:%s:%s:%s", file, line, job, step, ruleID)))
	return fmt.Sprintf("%x", sum[:8])
}
