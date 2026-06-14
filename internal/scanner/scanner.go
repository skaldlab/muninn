// Package scanner defines the interface that every scanner implementation
// must satisfy. Adding a new scanner means creating a file in this package
// that provides a type implementing Scanner.
package scanner

import (
	"context"

	"github.com/skaldlab/muninn/internal/config"
	"github.com/skaldlab/muninn/internal/normalizer"
)

// Scanner is the contract between the orchestrator and individual tool wrappers.
// Every scanner receives a target path, runs its underlying binary, and returns
// normalized findings. Implementations must not make real network calls during
// tests; use fixture data from testdata/ instead.
type Scanner interface {
	// Name returns the canonical lowercase name used in config and reporting
	// (e.g. "gitleaks", "semgrep"). This value must match the key used in
	// the muninn.yml scanners block.
	Name() string

	// Run executes the scanner against target (a filesystem path) and returns
	// all findings normalized to the common schema. Callers should treat a
	// non-nil error as a scanner execution failure, not a "findings found"
	// signal — presence of findings is indicated by a non-empty slice.
	Run(ctx context.Context, target string) ([]normalizer.Finding, error)

	// IsAvailable reports whether the scanner binary is present and executable
	// on PATH. The orchestrator calls this before Run to decide whether to skip
	// a scanner gracefully or return a hard error.
	IsAvailable() bool

	// Configure applies per-scanner options from the muninn.yml config block.
	// It must be called before Run. Implementations ignore fields that are not
	// relevant to their scanner.
	Configure(cfg config.ScannerConfig)
}
