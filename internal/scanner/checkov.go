package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Checkov wraps the Bridgecrew Checkov IaC misconfiguration scanner.
// See: https://github.com/bridgecrewio/checkov
type Checkov struct {
	// SkipChecks holds the list of Checkov check IDs to suppress
	// (e.g. ["CKV_AWS_18"]).
	SkipChecks []string
}

// Name implements Scanner.
func (c *Checkov) Name() string { return "checkov" }

// IsAvailable implements Scanner.
func (c *Checkov) IsAvailable() bool {
	// TODO: check exec.LookPath("checkov")
	return false
}

// Run implements Scanner.
func (c *Checkov) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke checkov --output json, parse output, normalize to []Finding
	return nil, nil
}
