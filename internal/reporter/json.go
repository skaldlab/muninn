package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// JSON writes findings as a pretty-printed JSON array.
// This is the machine-readable output consumed by downstream tooling.
type JSON struct{}

// Write implements Reporter.
func (j *JSON) Write(_ context.Context, w io.Writer, findings []normalizer.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("encoding findings as JSON: %w", err)
	}

	return nil
}
