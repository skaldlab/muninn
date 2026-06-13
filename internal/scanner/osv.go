package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// OSVScanner wraps the Google OSV-Scanner for dependency CVE detection.
// See: https://github.com/google/osv-scanner
type OSVScanner struct{}

// Name implements Scanner.
func (o *OSVScanner) Name() string { return "osv-scanner" }

// IsAvailable implements Scanner.
func (o *OSVScanner) IsAvailable() bool {
	// TODO: check exec.LookPath("osv-scanner")
	return false
}

// Run implements Scanner.
func (o *OSVScanner) Run(_ context.Context, _ string) ([]normalizer.Finding, error) {
	// TODO: invoke osv-scanner --format json, parse output, normalize to []Finding
	return nil, nil
}
