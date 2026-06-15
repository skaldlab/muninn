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
	return id + "\x00" + strings.ToLower(packageName(f)), true
}

// packageName reads the affected package from the metadata keys the dependency
// scanners use (osv-scanner: package; trivy: pkg_name).
func packageName(f normalizer.Finding) string {
	for _, k := range []string{"package", "pkg_name"} {
		if v, ok := f.Metadata[k].(string); ok {
			return v
		}
	}
	return ""
}

// mergeFinding folds a duplicate into the canonical finding: it appends the
// duplicate's scanner to DetectedBy and keeps the merged finding suppressed only
// when every scanner's variant was suppressed.
func mergeFinding(primary, dup normalizer.Finding) normalizer.Finding {
	tools := primary.DetectedBy
	if len(tools) == 0 {
		tools = []string{primary.Tool}
	}
	if !containsString(tools, dup.Tool) {
		tools = append(tools, dup.Tool)
	}
	// Only record DetectedBy once more than one distinct scanner is involved;
	// single-scanner findings convey their origin through Tool alone.
	if len(tools) > 1 {
		primary.DetectedBy = tools
	}
	primary.Suppressed = primary.Suppressed && dup.Suppressed
	return primary
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
