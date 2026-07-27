package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Tests in this file validate CHANGELOG.md, specifically the "[Unreleased]"
// entry added by the PR that raised the GitPython security floor to
// >=3.1.55 for GHSA-94p4-4cq8-9g67 (incomplete expandvars fix in
// create_remote / Remote.add).

const changelogPath = "CHANGELOG.md"

// versionHeadingRE matches a "## [x.y.z] - yyyy-mm-dd" released-version
// heading, distinct from the unreleased "## [Unreleased]" heading.
var versionHeadingRE = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`)

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

func TestChangelog_HasUnreleasedSection(t *testing.T) {
	changelog := readChangelog(t)
	if !strings.Contains(changelog, "## [Unreleased]") {
		t.Errorf("%s is missing a \"## [Unreleased]\" heading", changelogPath)
	}
}

func TestChangelog_UnreleasedSectionPrecedesLatestReleasedVersion(t *testing.T) {
	changelog := readChangelog(t)
	unreleasedIdx := strings.Index(changelog, "## [Unreleased]")
	if unreleasedIdx < 0 {
		t.Fatalf("%s has no \"## [Unreleased]\" heading", changelogPath)
	}

	loc := versionHeadingRE.FindStringIndex(changelog)
	if loc == nil {
		t.Fatalf("%s has no released \"## [x.y.z] - yyyy-mm-dd\" heading", changelogPath)
	}
	if unreleasedIdx >= loc[0] {
		t.Errorf("\"## [Unreleased]\" heading (offset %d) must come before the first released version heading (offset %d)", unreleasedIdx, loc[0])
	}
}

func TestChangelog_UnreleasedSectionUsesChangedSubheading(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)
	if !strings.Contains(section, "### Changed") {
		t.Errorf("[Unreleased] section is missing a \"### Changed\" subheading, got: %q", section)
	}
}

func TestChangelog_UnreleasedSectionDocumentsGitPythonFloorBump(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)

	for _, want := range []string{"GitPython", "3.1.55", "GHSA-94p4-4cq8-9g67"} {
		if !strings.Contains(section, want) {
			t.Errorf("[Unreleased] section is missing %q, got: %q", want, section)
		}
	}
}

func TestChangelog_UnreleasedEntryIsABulletListItem(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)

	idx := strings.Index(section, "GHSA-94p4-4cq8-9g67")
	if idx < 0 {
		t.Fatalf("[Unreleased] section does not mention GHSA-94p4-4cq8-9g67")
	}
	// Walk backwards to the start of the entry's line and confirm it (or the
	// bullet's first line, for wrapped entries) starts with "- ", matching
	// every other CHANGELOG.md entry's Markdown bullet-list convention.
	before := section[:idx]
	lineStart := strings.LastIndex(before, "\n- ")
	if lineStart < 0 && !strings.HasPrefix(strings.TrimLeft(section, "\n"), "- ") {
		t.Errorf("GitPython floor changelog entry does not appear to be a \"- \" bullet-list item")
	}
}

func TestChangelog_DoesNotReferenceStaleGitPythonFloorInUnreleased(t *testing.T) {
	changelog := readChangelog(t)
	section := unreleasedSection(t, changelog)
	if strings.Contains(section, "3.1.52") {
		t.Errorf("[Unreleased] section still references the superseded gitpython>=3.1.52 floor: %q", section)
	}
}

func TestChangelog_ReleasedVersionHeadingsAreWellFormed(t *testing.T) {
	changelog := readChangelog(t)
	matches := versionHeadingRE.FindAllString(changelog, -1)
	if len(matches) == 0 {
		t.Fatalf("no released version headings matched in %s; regex may be broken", changelogPath)
	}
	// The most recent prior release referenced by the PR description.
	const wantPrevRelease = "## [0.3.6] - 2026-07-22"
	if matches[0] != wantPrevRelease {
		t.Errorf("first released version heading = %q, want %q", matches[0], wantPrevRelease)
	}
}
