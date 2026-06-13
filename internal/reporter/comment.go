package reporter

import (
	"context"
	"io"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// Comment formats findings as Markdown suitable for posting as a GitHub PR
// review comment. Critical and high findings are highlighted with collapsible
// details blocks to keep the comment scannable.
type Comment struct{}

// Write implements Reporter.
func (c *Comment) Write(_ context.Context, _ io.Writer, _ []normalizer.Finding) error {
	// TODO: render findings as Markdown with severity icons, file links, and
	//       a summary table grouped by scanner.
	return nil
}
