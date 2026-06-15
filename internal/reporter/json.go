package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/skaldlab/muninn/internal/normalizer"
	"github.com/skaldlab/muninn/internal/version"
)

// JSON writes findings as a pretty-printed JSON object with a summary envelope.
// This is the machine-readable output consumed by downstream tooling.
type JSON struct{}

// jsonReport is the top-level envelope for the JSON output format.
type jsonReport struct {
	Version  string               `json:"version"`
	Tool     string               `json:"tool"`
	Summary  jsonSummary          `json:"summary"`
	Findings []normalizer.Finding `json:"findings"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Write implements Reporter.
func (j *JSON) Write(_ context.Context, w io.Writer, findings []normalizer.Finding) error {
	if findings == nil {
		findings = []normalizer.Finding{}
	}
	sorted := sortedJSONFindings(findings)
	report := jsonReport{
		Version:  version.Version,
		Tool:     "muninn",
		Summary:  buildJSONSummary(sorted),
		Findings: sorted,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}

// buildJSONSummary counts findings by severity.
func buildJSONSummary(findings []normalizer.Finding) jsonSummary {
	s := jsonSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case normalizer.SeverityCritical:
			s.Critical++
		case normalizer.SeverityHigh:
			s.High++
		case normalizer.SeverityMedium:
			s.Medium++
		case normalizer.SeverityLow:
			s.Low++
		case normalizer.SeverityInfo:
			s.Info++
		}
	}
	return s
}

// sortedJSONFindings returns a copy of findings sorted by severity (highest
// first), then by file path, then by line number.
func sortedJSONFindings(findings []normalizer.Finding) []normalizer.Finding {
	out := make([]normalizer.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := jsonSeverityRank(out[i].Severity), jsonSeverityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func jsonSeverityRank(s normalizer.Severity) int {
	switch s {
	case normalizer.SeverityCritical:
		return 5
	case normalizer.SeverityHigh:
		return 4
	case normalizer.SeverityMedium:
		return 3
	case normalizer.SeverityLow:
		return 2
	case normalizer.SeverityInfo:
		return 1
	default:
		return 0
	}
}
