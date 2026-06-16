package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/version"
)

// SARIF outputs findings in the Static Analysis Results Interchange Format
// (SARIF 2.1.0). The output is suitable for upload to the GitHub Security tab
// via the upload-sarif action.
type SARIF struct{}

// Write implements Reporter.
func (s *SARIF) Write(_ context.Context, w io.Writer, findings []normalizer.Finding) error {
	doc := s.buildDoc(findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SARIF document: %w", err)
	}
	return nil
}

func (s *SARIF) buildDoc(findings []normalizer.Finding) sarifDoc {
	active := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	run := sarifRun{
		Results: make([]sarifResult, 0, len(active)),
	}
	run.Tool.Driver.Name = "Muninn"
	run.Tool.Driver.Version = version.Version
	run.Tool.Driver.InformationURI = "https://github.com/skaldlab/muninn"
	run.Tool.Driver.Rules = s.buildRules(active)
	for _, f := range active {
		run.Results = append(run.Results, toSARIFResult(f))
	}
	return sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
}

func (s *SARIF) buildRules(findings []normalizer.Finding) []sarifRule {
	seen := make(map[string]bool)
	rules := make([]sarifRule, 0)
	for _, f := range findings {
		if f.RuleID == "" || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		rules = append(rules, sarifRule{
			ID:               f.RuleID,
			Name:             toPascalCase(f.RuleID),
			ShortDescription: sarifText{Text: f.Title},
			HelpURI:          f.RuleURL,
			DefaultConfiguration: sarifRuleConfig{
				Level: sarifSeverityLevel(f.Severity),
			},
		})
	}
	return rules
}

func toSARIFResult(f normalizer.Finding) sarifResult {
	r := sarifResult{
		RuleID:  f.RuleID,
		Level:   sarifSeverityLevel(f.Severity),
		Message: sarifText{Text: f.Title},
		Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifact{URI: f.File, URIBaseID: "%SRCROOT%"},
			Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Column},
		}}},
		Suppressions: []sarifSuppression{},
	}
	if f.Fingerprint != "" {
		r.Fingerprints = map[string]string{"primary": f.Fingerprint}
	}
	if f.Suppressed {
		r.Suppressions = []sarifSuppression{{Kind: "inSource", Justification: "suppressed"}}
	}
	if len(f.DetectedBy) > 1 {
		r.Properties = &sarifProperties{DetectedBy: f.DetectedBy}
	}
	return r
}

// sarifSeverityLevel maps a normalizer severity to a SARIF result level.
func sarifSeverityLevel(s normalizer.Severity) string {
	switch s {
	case normalizer.SeverityCritical, normalizer.SeverityHigh:
		return "error"
	case normalizer.SeverityMedium:
		return "warning"
	case normalizer.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// toPascalCase converts a kebab-case or snake_case identifier to PascalCase.
// Example: "aws-access-key" → "AwsAccessKey", "CKV_AWS_18" → "CkvAws18".
func toPascalCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	})
	var b strings.Builder
	for _, w := range words {
		if len(w) == 0 {
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]) + strings.ToLower(w[1:]))
	}
	return b.String()
}

// ── SARIF 2.1.0 schema types ─────────────────────────────────────────────────

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifText          `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Fingerprints map[string]string  `json:"fingerprints,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions"`
	Properties   *sarifProperties   `json:"properties,omitempty"`
}

// sarifProperties is a SARIF result property bag. Muninn uses it to record the
// full set of scanners that detected a deduplicated finding.
type sarifProperties struct {
	DetectedBy []string `json:"detectedBy,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}
