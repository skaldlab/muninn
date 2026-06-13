package reporter

import (
	"context"
	"io"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// SARIF outputs findings in the Static Analysis Results Interchange Format
// (SARIF 2.1.0). The output is suitable for upload to the GitHub Security tab
// via the upload-sarif action.
type SARIF struct{}

// Write implements Reporter.
func (s *SARIF) Write(_ context.Context, _ io.Writer, _ []normalizer.Finding) error {
	// TODO: marshal findings into SARIF 2.1.0 JSON schema
	return nil
}
