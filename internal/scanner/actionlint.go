package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Actionlint wraps the actionlint GitHub Actions linter.
// See: https://github.com/rhysd/actionlint
type Actionlint struct{}

// Name implements Scanner.
func (a *Actionlint) Name() string { return "actionlint" }

// IsAvailable implements Scanner.
func (a *Actionlint) IsAvailable() bool {
	// TODO: check exec.LookPath("actionlint")
	return false
}

// Run implements Scanner.
func (a *Actionlint) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke actionlint -format json, parse output, normalize to []Finding
	return nil, nil
}
