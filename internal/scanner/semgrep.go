package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Semgrep wraps the semgrep SAST scanner.
// See: https://semgrep.dev
type Semgrep struct {
	// Rulesets holds the list of semgrep rule identifiers to run,
	// sourced from the scanner's config block (e.g. ["p/security-audit"]).
	Rulesets []string
}

// Name implements Scanner.
func (s *Semgrep) Name() string { return "semgrep" }

// IsAvailable implements Scanner.
func (s *Semgrep) IsAvailable() bool {
	// TODO: check exec.LookPath("semgrep")
	return false
}

// Run implements Scanner.
func (s *Semgrep) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke semgrep --json with configured rulesets, normalize to []Finding
	return nil, nil
}
