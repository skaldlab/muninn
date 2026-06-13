package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Poutine wraps the poutine supply-chain pipeline risk scanner.
// See: https://github.com/boostsecurityio/poutine
type Poutine struct{}

// Name implements Scanner.
func (p *Poutine) Name() string { return "poutine" }

// IsAvailable implements Scanner.
func (p *Poutine) IsAvailable() bool {
	// TODO: check exec.LookPath("poutine")
	return false
}

// Run implements Scanner.
func (p *Poutine) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke poutine, parse JSON output, normalize to []Finding
	return nil, nil
}
