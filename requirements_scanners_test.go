package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Tests in this file validate the pip-compile lockfile pair touched by the PR
// that bumped zizmor 1.27.0 -> 1.28.0 and added a `gitpython>=3.1.52` security
// floor (resolved to gitpython==3.1.54 in the lockfile):
//
//   - requirements-scanners.in  (hand-edited top-level pins/floors)
//   - requirements-scanners.txt (hash-locked output of `make scanners-lock`)

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
	if got != "3.1.52" {
		t.Errorf("gitpython floor = %q, want 3.1.52", got)
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
	if got != "3.14.1" {
		t.Errorf("aiohttp floor = %q, want 3.14.1", got)
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
		{"locked release", lockedPinLineRE, "gitpython==3.1.54 \\", true},
		{"locked beta rejected", lockedPinLineRE, "gitpython==3.1.54beta1 \\", false},
	}
	for _, c := range cases {
		if got := c.re.MatchString(c.line); got != c.want {
			t.Errorf("%s: MatchString(%q) = %v, want %v", c.name, c.line, got, c.want)
		}
	}
}
func TestRequirementsScannersIn_GitPythonFloorHasRationaleComment(t *testing.T) {
	in := readRepoFile(t, requirementsScannersIn)
	idx := strings.Index(in, "gitpython>=3.1.52")
	if idx < 0 {
		t.Fatalf("gitpython>=3.1.52 floor not found in requirements-scanners.in")
	}
	preceding := in[:idx]
	// Every other security floor in this file documents the GHSA advisories it
	// fixes; the new gitpython floor should follow the same convention.
	if !strings.Contains(preceding, "GHSA-2f96-g7mh-g2hx") {
		t.Errorf("gitpython>=3.1.52 floor is missing its GHSA rationale comment")
	}
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

func TestRequirementsScannersTxt_GitPythonNoLongerOnStaleVulnerableVersion(t *testing.T) {
	txt := readRepoFile(t, requirementsScannersTxt)
	if strings.Contains(txt, "gitpython==3.1.50") {
		t.Errorf("requirements-scanners.txt still contains the stale, vulnerable gitpython==3.1.50 pin")
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
	if aiohttpFloor != "3.14.1" {
		t.Errorf("aiohttp floor = %q, want 3.14.1", aiohttpFloor)
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
