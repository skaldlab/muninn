package reporter

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/skaldlab/muninn/internal/normalizer"
)

const (
	commentMaxDesc       = 300
	commentMaxPerSection = 10
	// CommentIcon is the Muninn brand mark (Odin's raven); Unicode has no raven emoji.
	CommentIcon   = "🐦‍⬛"
	commentTitle  = "Muninn Security Scan"
	commentHeader = "## " + CommentIcon + " " + commentTitle + "\n\n"
	commentFooter = "\n*" + CommentIcon + " Powered by [Muninn](https://github.com/skaldlab/muninn) · [Skald Lab](https://skaldlab.dev)*"
	// CommentMarker is embedded in PR comments so Muninn can update the same thread.
	CommentMarker = "<!-- muninn:scan -->"
)

// Comment formats findings as Markdown suitable for posting as a GitHub PR
// review comment. Critical and high findings are highlighted with collapsible
// details blocks to keep the comment scannable.
type Comment struct{}

// Write implements Reporter.
func (c *Comment) Write(_ context.Context, w io.Writer, findings []normalizer.Finding) error {
	visible := visibleCommentFindings(findings)
	if len(visible) == 0 {
		return writeEmptyComment(w)
	}
	if _, err := fmt.Fprint(w, CommentMarker+"\n"+commentHeader); err != nil {
		return fmt.Errorf("comment header: %w", err)
	}
	if err := writeSummaryTable(w, visible); err != nil {
		return err
	}
	if err := writeFindingGroups(w, visible); err != nil {
		return err
	}
	return writeCommentFooter(w)
}

// visibleCommentFindings drops suppressed entries so PR comments match fail-on
// behaviour and avoid noise from intentional test fixtures.
func visibleCommentFindings(findings []normalizer.Finding) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

func writeEmptyComment(w io.Writer) error {
	const msg = CommentMarker + "\n" + commentHeader + "✅ No security issues found.\n\n"
	if _, err := fmt.Fprint(w, msg); err != nil {
		return fmt.Errorf("comment empty message: %w", err)
	}
	return writeCommentFooter(w)
}

func writeCommentFooter(w io.Writer) error {
	if _, err := fmt.Fprintln(w, commentFooter); err != nil {
		return fmt.Errorf("comment footer: %w", err)
	}
	return nil
}

func writeSummaryTable(w io.Writer, findings []normalizer.Finding) error {
	counts := make(map[normalizer.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	rows := []struct {
		label string
		sev   normalizer.Severity
	}{
		{"🔴 Critical", normalizer.SeverityCritical},
		{"🟠 High", normalizer.SeverityHigh},
		{"🟡 Medium", normalizer.SeverityMedium},
		{"🟢 Low", normalizer.SeverityLow},
		{"ℹ️ Info", normalizer.SeverityInfo},
	}
	if _, err := fmt.Fprint(w, "| Severity | Count |\n|----------|-------|\n"); err != nil {
		return fmt.Errorf("summary table header: %w", err)
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "| %s | %d |\n", row.label, counts[row.sev]); err != nil {
			return fmt.Errorf("summary table row: %w", err)
		}
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return fmt.Errorf("summary table newline: %w", err)
	}
	return nil
}

func writeFindingGroups(w io.Writer, findings []normalizer.Finding) error {
	type entry struct {
		sev   normalizer.Severity
		label string
	}
	order := []entry{
		{normalizer.SeverityCritical, "🔴 Critical"},
		{normalizer.SeverityHigh, "🟠 High"},
		{normalizer.SeverityMedium, "🟡 Medium"},
		{normalizer.SeverityLow, "🟢 Low"},
		{normalizer.SeverityInfo, "ℹ️ Info"},
	}
	groups := groupCommentBySeverity(findings)
	for _, e := range order {
		group := groups[e.sev]
		if len(group) == 0 {
			continue
		}
		if err := writeSeveritySection(w, e.label, group); err != nil {
			return err
		}
	}
	return nil
}

func groupCommentBySeverity(findings []normalizer.Finding) map[normalizer.Severity][]normalizer.Finding {
	groups := make(map[normalizer.Severity][]normalizer.Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	for sev := range groups {
		fs := groups[sev]
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].File != fs[j].File {
				return fs[i].File < fs[j].File
			}
			return fs[i].Line < fs[j].Line
		})
		groups[sev] = fs
	}
	return groups
}

func writeSeveritySection(w io.Writer, label string, findings []normalizer.Finding) error {
	if _, err := fmt.Fprintf(w, "### %s Findings\n\n", label); err != nil {
		return fmt.Errorf("section header: %w", err)
	}
	show := findings
	omitted := 0
	if len(findings) > commentMaxPerSection {
		show = findings[:commentMaxPerSection]
		omitted = len(findings) - commentMaxPerSection
	}
	for _, f := range show {
		if err := writeCommentFinding(w, f); err != nil {
			return err
		}
	}
	if omitted > 0 {
		if _, err := fmt.Fprintf(w, "*…and %d more %s finding(s) not shown.*\n\n", omitted, label); err != nil {
			return fmt.Errorf("section overflow note: %w", err)
		}
	}
	return nil
}

func writeCommentFinding(w io.Writer, f normalizer.Finding) error {
	title := f.Title
	if title == "" {
		title = f.RuleID
	}
	loc := fmt.Sprintf("%s:%d", f.File, f.Line)
	desc := truncateDesc(f.Description)
	_, err := fmt.Fprintf(w,
		"#### [%s] %s\n**File:** `%s`\n**Rule:** `%s`\n%s\n\n",
		f.Tool, title, loc, f.RuleID, desc)
	return err
}

func truncateDesc(s string) string {
	if len(s) <= commentMaxDesc {
		return s
	}
	return s[:commentMaxDesc] + "..."
}
