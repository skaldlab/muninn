// Package normalizer defines the unified finding schema that all scanners
// must normalize their output into. This single schema is the contract
// between scanner implementations and reporters.
package normalizer

// Severity represents how critical a finding is. Values map to the SARIF
// level taxonomy so SARIF reporters can translate without extra logic.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is the canonical output unit for every scanner in Muninn.
// All eight scanners produce []Finding; reporters consume []Finding.
// Scanner-specific fields that have no universal equivalent go in Metadata.
type Finding struct {
	// ID is a stable unique identifier for deduplication across runs.
	ID string `json:"id"`

	// Tool is the name of the scanner that produced this finding (e.g. "gitleaks").
	Tool string `json:"tool"`

	// DetectedBy lists every scanner that reported the same advisory when
	// findings for one CVE/GHSA from different scanners are merged into a single
	// finding. It is nil for findings reported by a single scanner; consult Tool
	// for those. The first entry is the canonical (primary) scanner.
	DetectedBy []string `json:"detected_by,omitempty"`

	// Severity is the normalized risk level.
	Severity Severity `json:"severity"`

	// Title is a short, human-readable summary suitable for a PR comment heading.
	Title string `json:"title"`

	// Description provides additional context about what was found and why it matters.
	Description string `json:"description"`

	// File is the repository-relative path where the finding was detected.
	File string `json:"file"`

	// Line is the 1-based line number of the finding.
	Line int `json:"line"`

	// Column is the 1-based column number. Zero means the scanner did not report one.
	Column int `json:"column,omitempty"`

	// RuleID is the scanner-native rule or check identifier (e.g. "generic-api-key").
	RuleID string `json:"rule_id"`

	// RuleURL links to documentation for the rule, if the scanner provides one.
	RuleURL string `json:"rule_url,omitempty"`

	// Fingerprint is a content-derived hash used to track findings across PRs
	// and suppress duplicates. Each scanner normalizer is responsible for
	// producing a stable fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Suppressed is true when the finding matches a suppression rule in muninn.yml.
	// Suppressed findings are included in JSON output but excluded from fail-on counts.
	Suppressed bool `json:"suppressed"`

	// Metadata holds scanner-specific fields that do not map to the universal schema.
	// Keys should use snake_case.
	Metadata map[string]any `json:"metadata,omitempty"`
}
