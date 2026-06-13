package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Gitleaks wraps the gitleaks secrets-detection binary.
// See: https://github.com/gitleaks/gitleaks
type Gitleaks struct{}

// Name implements Scanner.
func (g *Gitleaks) Name() string { return "gitleaks" }

// IsAvailable implements Scanner.
func (g *Gitleaks) IsAvailable() bool {
	// TODO: check exec.LookPath("gitleaks")
	return false
}

// Run implements Scanner.
func (g *Gitleaks) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke gitleaks, parse JSON output, normalize to []Finding
	return nil, nil
}
