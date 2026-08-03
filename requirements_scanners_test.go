package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These regression tests keep the hand-edited security floors in
// requirements-scanners.in synchronized with the hash-locked pins that
// `make scanners-lock` writes to requirements-scanners.txt. Without them a
// floor bump can land while the lockfile (and Docker image) stay on a
// vulnerable transitive version — the failure mode that left gitpython on
// 3.1.54 after GHSA-94p4-4cq8-9g67.

const (
	requirementsScannersIn  = "requirements-scanners.in"
	requirementsScannersTxt = "requirements-scanners.txt"
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// Version captures are fully numeric dotted forms (e.g. 3.14.1). Pre-release
// suffixes like rc/alpha/beta are rejected so compareVersions stays well-defined.
const numericVersionRE = `[0-9]+(?:\.[0-9]+)*`

// exactPinLineRE matches top-level "package==version" pin lines in the .in file.
var exactPinLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+)==(` + numericVersionRE + `)\s*$`)

// floorPinLineRE matches top-level "package>=version" floor lines in the .in file.
var floorPinLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+)>=(` + numericVersionRE + `)\s*$`)

// lockedPinLineRE matches "package==version \" entry header lines emitted by
// `uv pip compile --generate-hashes` in the .txt lockfile.
var lockedPinLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+)==(` + numericVersionRE + `) \\\s*$`)

// hashLineRE matches a single --hash=sha256:<64 hex chars> lockfile line, with
// an optional trailing line-continuation backslash.
var hashLineRE = regexp.MustCompile(`^\s*--hash=sha256:[0-9a-f]{64}\s*\\?\s*$`)

// parsePins extracts lowercased-name -> version for every match of re in text.
func parsePins(re *regexp.Regexp, text string) map[string]string {
	pins := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		pins[strings.ToLower(m[1])] = m[2]
	}
	return pins
}

// packageBlock returns the full lockfile entry for name: its "name==version \"
// header line plus every indented hash/"via" line that follows it, up to (but
// excluding) the next unindented line. Reports ok=false if name isn't locked.
func packageBlock(txt, name string) (block string, ok bool) {
	lines := strings.Split(txt, "\n")
	header := regexp.MustCompile(`(?i)^` + regexp.QuoteMeta(name) + `==`)
	start := -1
	for i, line := range lines {
		if header.MatchString(line) {
			start = i
			break
		}
	}
	if start == -1 {
		return "", false
	}
	end := start + 1
	for end < len(lines) && (strings.HasPrefix(lines[end], " ") || strings.HasPrefix(lines[end], "\t")) {
		end++
	}
	return strings.Join(lines[start:end], "\n"), true
}

// compareVersions compares two dotted-numeric version strings, returning -1,
// 0, or 1. Missing trailing components are treated as 0, so "3.1" == "3.1.0".
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.1.52", "3.1.54", -1},
		{"3.1.54", "3.1.52", 1},
		{"1.28.0", "1.28.0", 0},
		{"3.1.5", "3.1.50", -1}, // numeric, not lexicographic, comparison
		{"3.2", "3.1.99", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// ── requirements-scanners.in ────────────────────────────────────────────────

func TestRequirementsScannersIn_ZizmorPinnedToPatchedRelease(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	pins := parsePins(exactPinLineRE, in)
	got, ok := pins["zizmor"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no exact zizmor==... pin")
	}
	if got != "1.28.0" {
		t.Errorf("zizmor pin = %q, want 1.28.0", got)
	}
}

func TestRequirementsScannersIn_NoLongerReferencesYankedZizmorRelease(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	if strings.Contains(in, "1.27.0") {
		t.Errorf("requirements-scanners.in still references the yanked zizmor==1.27.0 release")
	}
}

func TestRequirementsScannersIn_GitPythonSecurityFloorAdded(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	floors := parsePins(floorPinLineRE, in)
	got, ok := floors["gitpython"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no gitpython>=... security floor")
	}
	if got != "3.1.55" {
		t.Errorf("gitpython floor = %q, want 3.1.55", got)
	}
}

func TestRequirementsScannersIn_AiohttpSecurityFloor(t *testing.T) {
	// Direct regression for the aiohttp CVE floor, independent of the generic
	// floor-vs-lockfile comparison in TestRequirementsScannersLockfile_AllFloorsSatisfied.
	in := readRepoFile(t, requirementsScannersIn)
	floors := parsePins(floorPinLineRE, in)
	got, ok := floors["aiohttp"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no aiohttp>=... security floor")
	}
	if got != "3.14.3" {
		t.Errorf("aiohttp floor = %q, want 3.14.3", got)
	}
}

func TestRequirementsScannersIn_CryptographySecurityFloor(t *testing.T) {
	// Direct regression for the cryptography CVE floor (GHSA-g6cj-pr64-35w5),
	// independent of the generic floor-vs-lockfile comparison below.
	in := readRepoFile(t, requirementsScannersIn)
	floors := parsePins(floorPinLineRE, in)
	got, ok := floors["cryptography"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no cryptography>=... security floor")
	}
	if got != "50.0.0" {
		t.Errorf("cryptography floor = %q, want 50.0.0", got)
	}
}

func TestPinVersionRegexRejectsPrereleaseSuffixes(t *testing.T) {
	cases := []struct {
		name string
		re   *regexp.Regexp
		line string
		want bool
	}{
		{"exact release", exactPinLineRE, "zizmor==1.28.0", true},
		{"exact rc rejected", exactPinLineRE, "zizmor==1.28.0rc1", false},
		{"floor release", floorPinLineRE, "aiohttp>=3.14.1", true},
		{"floor alpha rejected", floorPinLineRE, "aiohttp>=3.14.1a1", false},
		{"locked release", lockedPinLineRE, "gitpython==3.1.55 \\", true},
		{"locked beta rejected", lockedPinLineRE, "gitpython==3.1.55beta1 \\", false},
	}
	for _, c := range cases {
		if got := c.re.MatchString(c.line); got != c.want {
			t.Errorf("%s: MatchString(%q) = %v, want %v", c.name, c.line, got, c.want)
		}
	}
}

// TestPrecedingCommentBlock locks the helper that scopes GHSA rationale checks
// so an earlier unrelated advisory mention cannot satisfy a floor assertion.
func TestPrecedingCommentBlock(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "contiguous block above pin",
			text: "# keep aiohttp\naiohttp>=3.14.1\n\n# GHSA-94p4-4cq8-9g67\n# more rationale\n",
			want: "# GHSA-94p4-4cq8-9g67\n# more rationale",
		},
		{
			name: "ignores earlier unrelated comment",
			text: "# GHSA-94p4-4cq8-9g67 elsewhere\nsemgrep==1.0.0\n\n# only this block\n",
			want: "# only this block",
		},
		{
			name: "empty when previous line is not a comment",
			text: "semgrep==1.0.0\n\n",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := precedingCommentBlock(c.text); got != c.want {
				t.Errorf("precedingCommentBlock() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestRequirementsScannersIn_GitPythonFloorHasRationaleComment requires the
// GHSA that motivated the floor to sit in the comment block directly above it.
func TestRequirementsScannersIn_GitPythonFloorHasRationaleComment(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	idx := strings.Index(in, "gitpython>=3.1.55")
	if idx < 0 {
		t.Fatalf("gitpython>=3.1.55 floor not found in requirements-scanners.in")
	}
	// Only the contiguous comment block immediately above the floor counts;
	// an unrelated earlier GHSA mention must not satisfy this assertion.
	block := precedingCommentBlock(in[:idx])
	if !strings.Contains(block, "GHSA-94p4-4cq8-9g67") {
		t.Errorf("gitpython>=3.1.55 comment block is missing GHSA-94p4-4cq8-9g67, got: %q", block)
	}
}

// TestRequirementsScannersIn_GitPythonFloorCommentListsAllKnownGHSAs keeps prior
// advisories listed when a new GHSA is appended, so history is not silently dropped.
func TestRequirementsScannersIn_GitPythonFloorCommentListsAllKnownGHSAs(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	idx := strings.Index(in, "gitpython>=3.1.55")
	if idx < 0 {
		t.Fatalf("gitpython>=3.1.55 floor not found in requirements-scanners.in")
	}
	block := precedingCommentBlock(in[:idx])
	// The rationale comment accumulates every GHSA advisory that has driven a
	// gitpython floor bump so far; the new advisory should be appended, not
	// replace the earlier ones.
	for _, ghsa := range []string{
		"GHSA-2f96-g7mh-g2hx",
		"GHSA-956x-8gvw-wg5v",
		"GHSA-rwj8-pgh3-r573",
		"GHSA-v396-v7q4-x2qj",
		"GHSA-94p4-4cq8-9g67",
	} {
		if !strings.Contains(block, ghsa) {
			t.Errorf("gitpython floor rationale comment is missing %s, got: %q", ghsa, block)
		}
	}
}

// precedingCommentBlock returns the contiguous `# ...` lines at the end of
// text (typically the slice before a pin/floor line), ignoring a trailing
// blank line. Returns "" if the preceding non-blank content is not a comment.
func precedingCommentBlock(text string) string {
	lines := strings.Split(text, "\n")
	// Drop the empty string produced by a trailing newline so we inspect the
	// real last line of content.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	start := end
	for start > 0 {
		trimmed := strings.TrimSpace(lines[start-1])
		if !strings.HasPrefix(trimmed, "#") {
			break
		}
		start--
	}
	if start == end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

func TestRequirementsScannersIn_GitPythonFloorCompatibleWithCheckovConstraint(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	floor, ok := parsePins(floorPinLineRE, in)["gitpython"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no gitpython floor")
	}
	// The file's own comment says checkov==3.2.531 constrains gitpython to
	// <4,>=3.1.30; the new floor must sit inside that range or the resolver
	// would fail to produce a lockfile at all.
	if compareVersions(floor, "3.1.30") < 0 {
		t.Errorf("gitpython floor %q is below checkov's allowed gitpython>=3.1.30 minimum", floor)
	}
	if compareVersions(floor, "4.0.0") >= 0 {
		t.Errorf("gitpython floor %q violates checkov's allowed gitpython<4 ceiling", floor)
	}
}

// ── requirements-scanners.txt ───────────────────────────────────────────────

func TestRequirementsScannersTxt_ZizmorMatchesInPinExactly(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	txt := readRepoFile(t, requirementsScannersTxt)

	wantVersion, ok := parsePins(exactPinLineRE, in)["zizmor"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no zizmor pin to compare against")
	}

	got, ok := parsePins(lockedPinLineRE, txt)["zizmor"]
	if !ok {
		t.Fatalf("requirements-scanners.txt does not lock zizmor at all")
	}
	if got != wantVersion {
		t.Errorf("locked zizmor version = %q, want %q (must match requirements-scanners.in)", got, wantVersion)
	}
}

func TestRequirementsScannersTxt_ZizmorBlockHasValidHashesAndProvenance(t *testing.T) {
	txt := readRepoFile(t, requirementsScannersTxt)
	block, ok := packageBlock(txt, "zizmor")
	if !ok {
		t.Fatalf("requirements-scanners.txt has no zizmor entry")
	}
	if !strings.HasPrefix(block, "zizmor==1.28.0") {
		t.Errorf("zizmor block does not start with the expected pin, got: %q", block)
	}

	var hashCount int
	for _, line := range strings.Split(block, "\n") {
		if strings.Contains(line, "--hash=sha256:") {
			if !hashLineRE.MatchString(line) {
				t.Errorf("malformed hash line in zizmor block: %q", line)
			}
			hashCount++
		}
	}
	if hashCount == 0 {
		t.Errorf("zizmor block has no --hash=sha256:... entries")
	}

	if !strings.Contains(block, "# via -r requirements-scanners.in") {
		t.Errorf("zizmor block is missing the '# via -r requirements-scanners.in' provenance comment, got: %q", block)
	}
}

func TestRequirementsScannersTxt_GitPythonSatisfiesInFloor(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	txt := readRepoFile(t, requirementsScannersTxt)

	floor, ok := parsePins(floorPinLineRE, in)["gitpython"]
	if !ok {
		t.Fatalf("requirements-scanners.in has no gitpython floor to compare against")
	}

	locked, ok := parsePins(lockedPinLineRE, txt)["gitpython"]
	if !ok {
		t.Fatalf("requirements-scanners.txt does not lock gitpython at all")
	}

	if compareVersions(locked, floor) < 0 {
		t.Errorf("locked gitpython==%s is below the requirements-scanners.in floor gitpython>=%s", locked, floor)
	}
}

// TestRequirementsScannersTxt_GitPythonLockedAtExpectedVersion pins the
// resolved lockfile version so an accidental recompile onto another line fails CI.
func TestRequirementsScannersTxt_GitPythonLockedAtExpectedVersion(t *testing.T) {
	const want = "3.1.57"
	txt := readRepoFile(t, requirementsScannersTxt)
	got, ok := parsePins(lockedPinLineRE, txt)["gitpython"]
	if !ok {
		t.Fatalf("requirements-scanners.txt does not lock gitpython at all")
	}
	if got != want {
		t.Errorf("locked gitpython==%s, want %s", got, want)
	}
}

func TestRequirementsScannersTxt_GitPythonNoLongerOnStaleVulnerableVersion(t *testing.T) {
	txt := readRepoFile(t, requirementsScannersTxt)
	for _, stale := range []string{"gitpython==3.1.50", "gitpython==3.1.54"} {
		if strings.Contains(txt, stale) {
			t.Errorf("requirements-scanners.txt still contains the stale, vulnerable %s pin", stale)
		}
	}
}

func TestRequirementsScannersTxt_GitPythonBlockRecordsDirectAndTransitiveProvenance(t *testing.T) {
	txt := readRepoFile(t, requirementsScannersTxt)
	block, ok := packageBlock(txt, "gitpython")
	if !ok {
		t.Fatalf("requirements-scanners.txt has no gitpython entry")
	}

	var hashCount int
	for _, line := range strings.Split(block, "\n") {
		if strings.Contains(line, "--hash=sha256:") {
			if !hashLineRE.MatchString(line) {
				t.Errorf("malformed hash line in gitpython block: %q", line)
			}
			hashCount++
		}
	}
	if hashCount == 0 {
		t.Errorf("gitpython block has no --hash=sha256:... entries")
	}

	// requirements-scanners.in now pins gitpython directly (as a security
	// floor) while checkov still depends on it transitively, so uv must
	// record both provenance sources rather than just "# via checkov" as
	// before this PR.
	if !strings.Contains(block, "-r requirements-scanners.in") {
		t.Errorf("gitpython block is missing '-r requirements-scanners.in' provenance, got: %q", block)
	}
	if !strings.Contains(block, "checkov") {
		t.Errorf("gitpython block is missing 'checkov' provenance, got: %q", block)
	}
}

// ── cross-file consistency ──────────────────────────────────────────────────

func TestRequirementsScannersLockfile_AllExactPinsMatchSource(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	txt := readRepoFile(t, requirementsScannersTxt)

	pins := parsePins(exactPinLineRE, in)
	locked := parsePins(lockedPinLineRE, txt)

	if len(pins) == 0 {
		t.Fatalf("no exact pins parsed from requirements-scanners.in; regex may be broken")
	}

	for name, wantVersion := range pins {
		gotVersion, ok := locked[name]
		if !ok {
			t.Errorf("requirements-scanners.in pins %s==%s but requirements-scanners.txt does not lock it at all", name, wantVersion)
			continue
		}
		if gotVersion != wantVersion {
			t.Errorf("requirements-scanners.in pins %s==%s but requirements-scanners.txt locks %s==%s", name, wantVersion, name, gotVersion)
		}
	}
}

func TestRequirementsScannersLockfile_AllFloorsSatisfied(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	txt := readRepoFile(t, requirementsScannersTxt)

	floors := parsePins(floorPinLineRE, in)
	locked := parsePins(lockedPinLineRE, txt)

	if len(floors) == 0 {
		t.Fatalf("no floor pins parsed from requirements-scanners.in; regex may be broken")
	}

	aiohttpFloor, ok := floors["aiohttp"]
	if !ok {
		t.Fatalf("requirements-scanners.in missing aiohttp>=... security floor")
	}
	if aiohttpFloor != "3.14.3" {
		t.Errorf("aiohttp floor = %q, want 3.14.3", aiohttpFloor)
	}

	cryptographyFloor, ok := floors["cryptography"]
	if !ok {
		t.Fatalf("requirements-scanners.in missing cryptography>=... security floor")
	}
	if cryptographyFloor != "50.0.0" {
		t.Errorf("cryptography floor = %q, want 50.0.0", cryptographyFloor)
	}

	for name, floor := range floors {
		gotVersion, ok := locked[name]
		if !ok {
			t.Errorf("requirements-scanners.in floors %s>=%s but requirements-scanners.txt does not lock it at all", name, floor)
			continue
		}
		if compareVersions(gotVersion, floor) < 0 {
			t.Errorf("requirements-scanners.in floors %s>=%s but requirements-scanners.txt only locks %s==%s", name, floor, name, gotVersion)
		}
	}
}
