// Package reporter contains output formatters that consume []normalizer.Finding
// and produce the three supported report formats: SARIF, GitHub PR comment
// Markdown, and structured JSON.
package reporter

import (
	"context"
	"io"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Reporter is the common interface for all output formatters.
type Reporter interface {
	// Write formats findings and writes them to w.
	// Implementations must respect ctx cancellation.
	Write(ctx context.Context, w io.Writer, findings []normalizer.Finding) error
}
