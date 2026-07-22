package main

// Tests for requirements-scanners.in / requirements-scanners.txt, the
// pip-tools source and hash-locked lockfile for the pip-installed scanners
// (semgrep, checkov, zizmor). These guard the changes that:
//   - bumped zizmor to 1.28.0 (both files), and
//   - added a gitpython>=3.1.52 security floor to the .in file, which pulled
//     gitpython 3.1.54 into the lockfile with an updated "via" trail.
//
// The checks below parse the two files directly rather than hardcoding
// today's exact hashes wherever avoidable, so they keep validating the
// *shape* of the pins (floor documented, lockfile satisfies the floor, hashes
// well-formed) even as Renovate/`make scanners-lock` bumps versions further.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	requirementsScannersIn  = "requirements-scanners.in"
	requirementsScannersTxt = "requirements-scanners.txt"
)

// pkgPinRE matches a top-level "name==version" or "name>=version" directive
// line in requirements-scanners.in (comments and blank lines don't match).
var pkgPinRE = regexp.MustCompile(`(?m)^([A-Za-z0-9_.\-]+)(==|>=)([0-9][0-9A-Za-z.\-]*)$`)

// txtPkgLineRE matches the start of a pinned-package block in the compiled
// requirements-scanners.txt, e.g. "gitpython==3.1.54 \".
var txtPkgLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9_.\-]+)==([^\s\\]+)`)

// txtHashRE extracts the hex digest from a "--hash=sha256:<hex>" line.
var txtHashRE = regexp.MustCompile(`--hash=sha256:([0-9a-f]+)`)

// readTestFile reads a file relative to the repo root (the package
// directory), which is how other tests in this package (main_test.go) read
// testdata.
func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(data)
}

// inFloors returns the ">="-style security-floor directives declared in
// requirements-scanners.in, keyed by package name.
func inFloors(t *testing.T, content string) map[string]string {
	t.Helper()
	floors := map[string]string{}
	for _, m := range pkgPinRE.FindAllStringSubmatch(content, -1) {
		name, op, version := m[1], m[2], m[3]
		if op == ">=" {
			floors[name] = version
		}
	}
	return floors
}

// inPins returns the "=="-style exact pins declared in
// requirements-scanners.in, keyed by package name.
func inPins(t *testing.T, content string) map[string]string {
	t.Helper()
	pins := map[string]string{}
	for _, m := range pkgPinRE.FindAllStringSubmatch(content, -1) {
		name, op, version := m[1], m[2], m[3]
		if op == "==" {
			pins[name] = version
		}
	}
	return pins
}

// txtBlock isolates the compiled-lockfile block for pkg (from its
// "name==version \" line up to, but not including, the next top-level
// package line or EOF), plus the pinned version.
func txtBlock(t *testing.T, content, pkg string) (block, version string) {
	t.Helper()
	locs := txtPkgLineRE.FindAllStringSubmatchIndex(content, -1)
	for i, loc := range locs {
		name := content[loc[2]:loc[3]]
		if name != pkg {
			continue
		}
		start := loc[0]
		end := len(content)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		return content[start:end], content[loc[4]:loc[5]]
	}
	t.Fatalf("no %q entry found in %s", pkg, requirementsScannersTxt)
	return "", ""
}

// txtHashes returns every sha256 hex digest attached to a lockfile block.
func txtHashes(block string) []string {
	var hashes []string
	for _, m := range txtHashRE.FindAllStringSubmatch(block, -1) {
		hashes = append(hashes, m[1])
	}
	return hashes
}

// compareVersions compares two dotted numeric version strings (e.g.
// "3.1.52" vs "3.1.54"). It returns -1, 0, or 1, mirroring strings.Compare's
// convention. Non-numeric or missing trailing components are treated as 0,
// so "1.28" == "1.28.0".
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
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

// ── compareVersions ─────────────────────────────────────────────────────────

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"3.1.52", "3.1.54", -1},
		{"3.1.54", "3.1.52", 1},
		{"3.1.52", "3.1.52", 0},
		{"1.28.0", "1.27.0", 1},
		{"1.28", "1.28.0", 0},
		{"3.14.1", "3.9.0", 1}, // numeric, not lexicographic, comparison
		{"3.9.0", "3.14.1", -1},
		{"2", "2.0.0", 0},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// ── requirements-scanners.in ────────────────────────────────────────────────

func TestRequirementsScannersIn_ZizmorPinnedTo1_28_0(t *testing.T) {
	content := readTestFile(t, requirementsScannersIn)
	pins := inPins(t, content)
	got, ok := pins["zizmor"]
	if !ok {
		t.Fatalf("zizmor is not an exact (==) pin in %s; pins: %v", requirementsScannersIn, pins)
	}
	if got != "1.28.0" {
		t.Errorf("zizmor pin = %q, want %q", got, "1.28.0")
	}
}

func TestRequirementsScannersIn_GitPythonSecurityFloor(t *testing.T) {
	content := readTestFile(t, requirementsScannersIn)

	floors := inFloors(t, content)
	got, ok := floors["gitpython"]
	if !ok {
		t.Fatalf("gitpython has no >= security floor in %s; floors: %v", requirementsScannersIn, floors)
	}
	if got != "3.1.52" {
		t.Errorf("gitpython floor = %q, want %q", got, "3.1.52")
	}

	// gitpython must not also be exact-pinned; the whole point of a floor is
	// to let checkov's own gitpython<4,>=3.1.30 constraint pick the resolved
	// version, only forcing it above the patched line.
	if pins := inPins(t, content); pins["gitpython"] != "" {
		t.Errorf("gitpython is exact-pinned (==%s) as well as floored; expected only a >= floor", pins["gitpython"])
	}

	// The floor must be documented with the GHSA advisories it fixes, so a
	// future reader (or Renovate) understands why it can't be relaxed.
	wantAdvisories := []string{
		"GHSA-2f96-g7mh-g2hx",
		"GHSA-956x-8gvw-wg5v",
		"GHSA-rwj8-pgh3-r573",
		"GHSA-v396-v7q4-x2qj",
	}
	idx := strings.Index(content, "gitpython>=3.1.52")
	if idx == -1 {
		t.Fatalf("could not locate gitpython>=3.1.52 line in %s", requirementsScannersIn)
	}
	// The explanatory comment precedes the directive line.
	preamble := content[:idx]
	for _, advisory := range wantAdvisories {
		if !strings.Contains(preamble, advisory) {
			t.Errorf("comment preceding gitpython floor is missing advisory %s", advisory)
		}
	}
	if !strings.Contains(preamble, "gitpython<4,>=3.1.30") {
		t.Errorf("comment preceding gitpython floor should note checkov's own gitpython<4,>=3.1.30 constraint")
	}
}

func TestRequirementsScannersIn_NoDuplicateDirectives(t *testing.T) {
	content := readTestFile(t, requirementsScannersIn)
	seen := map[string]int{}
	for _, m := range pkgPinRE.FindAllStringSubmatch(content, -1) {
		seen[m[1]]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("%s appears %d times as a top-level directive in %s, want at most once", name, count, requirementsScannersIn)
		}
	}
	if seen["gitpython"] != 1 {
		t.Errorf("expected exactly one gitpython directive, got %d", seen["gitpython"])
	}
	if seen["zizmor"] != 1 {
		t.Errorf("expected exactly one zizmor directive, got %d", seen["zizmor"])
	}
}

// ── requirements-scanners.txt ───────────────────────────────────────────────

func TestRequirementsScannersTxt_ZizmorPinnedAndHashed(t *testing.T) {
	content := readTestFile(t, requirementsScannersTxt)
	block, version := txtBlock(t, content, "zizmor")

	if version != "1.28.0" {
		t.Errorf("zizmor pinned version = %q, want %q", version, "1.28.0")
	}

	hashes := txtHashes(block)
	if len(hashes) != 11 {
		t.Errorf("zizmor has %d hashes, want 11", len(hashes))
	}
	assertValidSha256Hashes(t, "zizmor", hashes)

	if !strings.Contains(block, "-r requirements-scanners.in") {
		t.Errorf("zizmor block should note it's required via -r requirements-scanners.in, block:\n%s", block)
	}
}

func TestRequirementsScannersTxt_GitPythonPinnedAndHashed(t *testing.T) {
	content := readTestFile(t, requirementsScannersTxt)
	block, version := txtBlock(t, content, "gitpython")

	if version != "3.1.54" {
		t.Errorf("gitpython pinned version = %q, want %q", version, "3.1.54")
	}

	hashes := txtHashes(block)
	if len(hashes) != 2 {
		t.Errorf("gitpython has %d hashes, want 2", len(hashes))
	}
	assertValidSha256Hashes(t, "gitpython", hashes)

	// Now that requirements-scanners.in declares gitpython>=3.1.52 directly,
	// the lockfile's "via" trail must credit both the direct requirement and
	// the transitive one from checkov.
	if !strings.Contains(block, "-r requirements-scanners.in") {
		t.Errorf("gitpython block should list -r requirements-scanners.in as a via source, block:\n%s", block)
	}
	if !strings.Contains(block, "checkov") {
		t.Errorf("gitpython block should still list checkov as a via source, block:\n%s", block)
	}
}

func TestRequirementsScannersTxt_GitPythonMeetsSecurityFloor(t *testing.T) {
	inContent := readTestFile(t, requirementsScannersIn)
	txtContent := readTestFile(t, requirementsScannersTxt)

	floor, ok := inFloors(t, inContent)["gitpython"]
	if !ok {
		t.Fatalf("gitpython has no floor declared in %s", requirementsScannersIn)
	}
	_, pinned := txtBlock(t, txtContent, "gitpython")

	if compareVersions(pinned, floor) < 0 {
		t.Errorf("locked gitpython version %s does not satisfy the >=%s security floor from %s", pinned, floor, requirementsScannersIn)
	}
}

// TestRequirementsScannersTxt_AllFloorsSatisfied is a generalized regression
// check: every ">=" security floor declared in requirements-scanners.in
// (gitpython's new one, plus any others like aiohttp's) must be met by the
// version actually resolved into requirements-scanners.txt. This protects
// against `make scanners-lock` being run against a stale/edited .in that
// silently drops below a documented floor.
func TestRequirementsScannersTxt_AllFloorsSatisfied(t *testing.T) {
	inContent := readTestFile(t, requirementsScannersIn)
	txtContent := readTestFile(t, requirementsScannersTxt)

	floors := inFloors(t, inContent)
	if len(floors) == 0 {
		t.Fatalf("expected at least one >= security floor in %s", requirementsScannersIn)
	}

	for pkg, floor := range floors {
		_, pinned := txtBlock(t, txtContent, pkg)
		if compareVersions(pinned, floor) < 0 {
			t.Errorf("%s: locked version %s does not satisfy the >=%s floor from %s", pkg, pinned, floor, requirementsScannersIn)
		}
	}
}

func TestRequirementsScannersTxt_ZizmorHashesChangedFromPriorRelease(t *testing.T) {
	// Sanity/regression check: the previous zizmor==1.27.0 hash for
	// sha256:0bba3eff43f919b04b9b6365b4ef17437649e11eafb73f603407873b65ad01dd
	// must not still be present now that the pin moved to 1.28.0 - a stale
	// hash left behind would mean the lockfile wasn't actually regenerated.
	content := readTestFile(t, requirementsScannersTxt)
	block, _ := txtBlock(t, content, "zizmor")
	staleHash := "0bba3eff43f919b04b9b6365b4ef17437649e11eafb73f603407873b65ad01dd"
	if strings.Contains(block, staleHash) {
		t.Errorf("zizmor block still contains a hash from the old 1.27.0 pin: %s", staleHash)
	}
}

// assertValidSha256Hashes checks that every hash for pkg is a well-formed,
// unique 64-character lowercase hex sha256 digest.
func assertValidSha256Hashes(t *testing.T, pkg string, hashes []string) {
	t.Helper()
	if len(hashes) == 0 {
		t.Fatalf("%s: no hashes found", pkg)
	}
	seen := map[string]bool{}
	for _, h := range hashes {
		if len(h) != 64 {
			t.Errorf("%s: hash %q has length %d, want 64", pkg, h, len(h))
		}
		if strings.ToLower(h) != h {
			t.Errorf("%s: hash %q is not lowercase", pkg, h)
		}
		if seen[h] {
			t.Errorf("%s: duplicate hash %q", pkg, h)
		}
		seen[h] = true
	}
}
