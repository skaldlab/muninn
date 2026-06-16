package main

import (
	"strings"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// dedupeByAdvisory collapses findings that report the same vulnerability — the
// same advisory (CVE/GHSA) for the same package, detected by more than one
// scanner — into a single finding, recording every reporting scanner in
// DetectedBy. The first finding in pipeline order is kept as the canonical
// entry. Findings without an advisory id (secrets, SAST, IaC) are never merged.
// Input order is otherwise preserved.
func dedupeByAdvisory(findings []normalizer.Finding) []normalizer.Finding {
	indexByKey := make(map[string]int)
	out := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		key, ok := advisoryKey(f)
		if !ok {
			out = append(out, f)
			continue
		}
		if i, seen := indexByKey[key]; seen {
			out[i] = mergeFinding(out[i], f)
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, f)
	}
	return out
}

// advisoryKey returns the deduplication key for a finding (advisory id scoped to
// the affected package, so the same CVE on two different packages stays
// separate) and whether the finding is deduplicatable at all.
func advisoryKey(f normalizer.Finding) (string, bool) {
	id := normalizer.AdvisoryID(f)
	if id == "" {
		return "", false
	}
	return id + "\x00" + strings.ToLower(normalizer.PackageName(f)), true
}

// mergeFinding folds a duplicate into the canonical finding: it records the
// duplicate's scanner in DetectedBy, its location in Sources, and keeps the
// merged finding suppressed only when every scanner's variant was suppressed.
func mergeFinding(primary, dup normalizer.Finding) normalizer.Finding {
	tools := primary.DetectedBy
	if len(tools) == 0 {
		tools = []string{primary.Tool}
	}
	if !containsString(tools, dup.Tool) {
		tools = append(tools, dup.Tool)
	}
	sources := primary.Sources
	if len(sources) == 0 {
		sources = []normalizer.FindingSource{{Tool: primary.Tool, File: primary.File}}
	}
	cand := normalizer.FindingSource{Tool: dup.Tool, File: dup.File}
	if !containsSource(sources, cand) {
		sources = append(sources, cand)
	}
	// Only record DetectedBy/Sources once more than one distinct scanner is
	// involved; single-scanner findings convey origin through Tool and File.
	if len(tools) > 1 {
		primary.DetectedBy = tools
		primary.Sources = sources
	}
	primary.Suppressed = primary.Suppressed && dup.Suppressed
	return primary
}

// containsSource reports whether srcs already contains the tool+file pair v.
func containsSource(srcs []normalizer.FindingSource, v normalizer.FindingSource) bool {
	for _, s := range srcs {
		if s == v {
			return true
		}
	}
	return false
}

// containsString reports whether s contains v.
func containsString(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
