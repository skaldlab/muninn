package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Zizmor wraps the zizmor CI/CD pipeline security scanner.
// See: https://github.com/woodruffw/zizmor
type Zizmor struct{}

// Name implements Scanner.
func (z *Zizmor) Name() string { return "zizmor" }

// IsAvailable implements Scanner.
func (z *Zizmor) IsAvailable() bool {
	// TODO: check exec.LookPath("zizmor")
	return false
}

// Run implements Scanner.
func (z *Zizmor) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke zizmor, parse SARIF output, normalize to []Finding
	return nil, nil
}
