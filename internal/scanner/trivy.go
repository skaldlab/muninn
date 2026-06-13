package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Trivy wraps the Aqua Security Trivy container and filesystem scanner.
// See: https://github.com/aquasecurity/trivy
type Trivy struct {
	// Severities is the list of severity levels to include (e.g. ["CRITICAL", "HIGH"]).
	Severities []string

	// IgnoreUnfixed instructs trivy to skip vulnerabilities with no available fix.
	IgnoreUnfixed bool
}

// Name implements Scanner.
func (t *Trivy) Name() string { return "trivy" }

// IsAvailable implements Scanner.
func (t *Trivy) IsAvailable() bool {
	// TODO: check exec.LookPath("trivy")
	return false
}

// Run implements Scanner.
func (t *Trivy) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke trivy --format json, parse output, normalize to []Finding
	return nil, nil
}
