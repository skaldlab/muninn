package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Tests in this file keep the Unreleased CHANGELOG entry honest about the
// GitPython floor bump: without them a security-floor change can ship while
// the human-readable history still points at a stale advisory or version.

const changelogPath = "CHANGELOG.md"

// versionHeadingPattern matches a "## [x.y.z] - yyyy-mm-dd" released-version
// heading, distinct from the unreleased "## [Unreleased]" heading.
const versionHeadingPattern = `(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`

func readChangelog(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Fatalf("read %s: %v", changelogPath, err)
	}
	return string(data)
}

// unreleasedSection returns the text of the "## [Unreleased]" section, i.e.
// everything between that heading and the next "## " heading (exclusive).
func unreleasedSection(t *testing.T, changelog string) string {
	t.Helper()
	const heading = "## [Unreleased]"
	start := strings.Index(changelog, heading)
	if start < 0 {
		t.Fatalf("%s has no %q heading", changelogPath, heading)
	}
	rest := changelog[start+len(heading):]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// bulletEntryContaining returns the "- " bullet entry (including indented
// wrap continuations) that contains needle. ok is false when needle sits in
// unbulleted prose, even if an earlier bullet appears above it.
func bulletEntryContaining(section, needle string) (string, bool) {
	idx := strings.Index(section, needle)
	if idx < 0 {
		return "", false
	}
	lines := strings.Split(section, "\n")
	lineIdx := strings.Count(section[:idx], "\n")

	start := lineIdx
	for start >= 0 {
		line := lines[start]
		if strings.HasPrefix(line, "- ") {
			break
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			return "", false
		}
		// Bare (unindented) prose is not part of an entry — including when the
		// advisory itself is on that line immediately under a prior bullet.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			return "", false
		}
		start--
	}
	if start < 0 || !strings.HasPrefix(lines[start], "- ") {
		return "", false
	}

	end := lineIdx + 1
	for end < len(lines) {
		line := lines[end]
		if strings.HasPrefix(line, "- ") || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			break
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		end++
	}
	return strings.Join(lines[start:end], "\n"), true
}

// TestChangelog_HasUnreleasedSection requires an Unreleased heading so
// security-floor bumps have a place to land before the next tagged release.
func TestChangelog_HasUnreleasedSection(t *testing.T) {
	changelog := readChangelog(t)
	if !strings.Contains(changelog, "## [Unreleased]") {
		t.Errorf("%s is missing a \"## [Unreleased]\" heading", changelogPath)
	}
}

// TestChangelog_UnreleasedSectionPrecedesLatestReleasedVersion keeps newest
// notes above released history so readers see pending security bumps first.
func TestChangelog_UnreleasedSectionPrecedesLatestReleasedVersion(t *testing.T) {
	changelog := readChangelog(t)
	unreleasedIdx := strings.Index(changelog, "## [Unreleased]")
	if unreleasedIdx < 0 {
		t.Fatalf("%s has no \"## [Unreleased]\" heading", changelogPath)
	}

	re := regexp.MustCompile(versionHeadingPattern)
	loc := re.FindStringIndex(changelog)
	if loc == nil {
		t.Fatalf("%s has no released \"## [x.y.z] - yyyy-mm-dd\" heading", changelogPath)
	}
	if unreleasedIdx >= loc[0] {
		t.Errorf("\"## [Unreleased]\" heading (offset %d) must come before the first released version heading (offset %d)", unreleasedIdx, loc[0])
	}
}

// TestChangelog_UnreleasedSectionUsesChangedSubheading requires the Changed
// bucket so dependency-floor bumps stay with other non-breaking updates.
func TestChangelog_UnreleasedSectionUsesChangedSubheading(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)
	if !strings.Contains(section, "### Changed") {
		t.Errorf("[Unreleased] section is missing a \"### Changed\" subheading, got: %q", section)
	}
}

// TestChangelog_DocumentsGitPythonFloorBump ensures the advisory and floor
// version remain recorded where operators look for remediations (released or
// unreleased notes).
func TestChangelog_DocumentsGitPythonFloorBump(t *testing.T) {
	changelog := readChangelog(t)

	for _, want := range []string{"GitPython", "3.1.55", "GHSA-94p4-4cq8-9g67"} {
		if !strings.Contains(changelog, want) {
			t.Errorf("%s is missing %q", changelogPath, want)
		}
	}
}

// TestChangelog_GitPythonFloorEntryIsABulletListItem rejects advisory mentions
// that only appear in unbulleted prose after another list item.
func TestChangelog_GitPythonFloorEntryIsABulletListItem(t *testing.T) {
	changelog := readChangelog(t)

	entry, ok := bulletEntryContaining(changelog, "GHSA-94p4-4cq8-9g67")
	if !ok {
		t.Errorf("GitPython floor changelog entry does not appear to be a \"- \" bullet-list item")
	}
	if ok && !strings.Contains(entry, "GHSA-94p4-4cq8-9g67") {
		t.Errorf("bullet entry missing GHSA-94p4-4cq8-9g67, got: %q", entry)
	}
}

// TestChangelog_DoesNotReferenceStaleGitPythonFloorInUnreleased blocks the
// superseded 3.1.52 floor from lingering in pending notes after the bump.
func TestChangelog_DoesNotReferenceStaleGitPythonFloorInUnreleased(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)
	if strings.Contains(section, "3.1.52") {
		t.Errorf("[Unreleased] section still references the superseded gitpython>=3.1.52 floor: %q", section)
	}
}

// TestChangelog_ReleasedVersionHeadingsAreWellFormed checks every released
// heading matches ## [x.y.z] - yyyy-mm-dd without pinning a specific version.
func TestChangelog_ReleasedVersionHeadingsAreWellFormed(t *testing.T) {
	changelog := readChangelog(t)
	re := regexp.MustCompile(versionHeadingPattern)

	var found int
	for _, line := range strings.Split(changelog, "\n") {
		if !strings.HasPrefix(line, "## [") || strings.HasPrefix(line, "## [Unreleased]") {
			continue
		}
		found++
		if !re.MatchString(line) {
			t.Errorf("released heading %q is not well-formed (want ## [x.y.z] - yyyy-mm-dd)", line)
		}
	}
	if found == 0 {
		t.Fatalf("no released version headings found in %s", changelogPath)
	}
}

// TestBulletEntryContaining prevents the bullet-scoping helper from accepting
// adjacent unbulleted advisory prose as part of a preceding list item.
func TestBulletEntryContaining(t *testing.T) {
	cases := []struct {
		name    string
		section string
		wantOK  bool
	}{
		{
			name: "wrapped bullet containing advisory",
			section: `
- GitPython floor raised for GHSA-94p4-4cq8-9g67 (incomplete
  expandvars fix).
`,
			wantOK: true,
		},
		{
			name: "unbulleted prose after blank line fails",
			section: `
- Unrelated change.

GitPython floor raised for GHSA-94p4-4cq8-9g67 without a bullet.
`,
			wantOK: false,
		},
		{
			name: "bare advisory line directly after bullet fails",
			section: `
- Unrelated change.
GitPython floor raised for GHSA-94p4-4cq8-9g67 without a bullet.
`,
			wantOK: false,
		},
		{
			name: "advisory on bullet opener",
			section: `
- Mentions GHSA-94p4-4cq8-9g67 directly.
`,
			wantOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry, ok := bulletEntryContaining(c.section, "GHSA-94p4-4cq8-9g67")
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (entry=%q)", ok, c.wantOK, entry)
			}
			if ok && !strings.Contains(entry, "GHSA-94p4-4cq8-9g67") {
				t.Errorf("entry missing advisory: %q", entry)
			}
		})
	}
}
