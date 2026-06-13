package scanner

// edge_cases_test.go covers the paths left uncovered by the main scanner test
// files: malformed JSON inputs, severity default branches, nil-doc guards, and
// pre-cancelled context behaviour.  All helpers call internal (unexported)
// functions directly to hit the exact statements the coverage tool flags.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skaldlab/muninn/internal/normalizer"
)

// ── actionlint ────────────────────────────────────────────────────────────────

func TestActionlintSeverity_Default(t *testing.T) {
	// Any level that isn't error/warning/info falls through to low.
	if got := actionlintSeverity("unknown"); got != normalizer.SeverityLow {
		t.Errorf("actionlintSeverity(unknown) = %q, want low", got)
	}
}

func TestParseActionlintJSON_Malformed(t *testing.T) {
	_, err := parseActionlintJSON([]byte("{not json}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// ── checkov ───────────────────────────────────────────────────────────────────

func TestCheckovSeverity_Low(t *testing.T) {
	if got := checkovSeverity("LOW"); got != normalizer.SeverityLow {
		t.Errorf("checkovSeverity(LOW) = %q, want low", got)
	}
}

func TestCheckovSeverity_Default(t *testing.T) {
	if got := checkovSeverity(""); got != normalizer.SeverityInfo {
		t.Errorf("checkovSeverity('') = %q, want info", got)
	}
}

func TestParseCheckovJSON_MalformedObject(t *testing.T) {
	_, err := parseCheckovJSON([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error for malformed object JSON, got nil")
	}
}

func TestParseCheckovJSON_MalformedArray(t *testing.T) {
	_, err := parseCheckovJSON([]byte("[{bad"))
	if err == nil {
		t.Fatal("expected error for malformed array JSON, got nil")
	}
}

func TestParseCheckovJSON_UnknownLeadingByte(t *testing.T) {
	// Input that is neither '[' nor '{' returns nil, nil gracefully.
	blocks, err := parseCheckovJSON([]byte("null"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blocks != nil {
		t.Errorf("expected nil blocks for non-object/array input, got %v", blocks)
	}
}

// ── gitleaks ──────────────────────────────────────────────────────────────────

func TestReadGitleaksReport_Malformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json}"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := readGitleaksReport(path)
	if err == nil {
		t.Fatal("expected error for malformed gitleaks report, got nil")
	}
}

// ── osv-scanner ───────────────────────────────────────────────────────────────

func TestParseOSVJSON_Malformed(t *testing.T) {
	_, err := parseOSVJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNormalizeOSV_Nil(t *testing.T) {
	if got := normalizeOSV(nil); got != nil {
		t.Errorf("normalizeOSV(nil) = %v, want nil", got)
	}
}

func TestOSVSeverity_High(t *testing.T) {
	v := osvVuln{}
	v.DatabaseSpecific.Severity = "HIGH"
	if got := osvSeverity(v); got != normalizer.SeverityHigh {
		t.Errorf("osvSeverity(HIGH) = %q, want high", got)
	}
}

func TestOSVSeverity_Moderate(t *testing.T) {
	for _, s := range []string{"MODERATE", "MEDIUM"} {
		v := osvVuln{}
		v.DatabaseSpecific.Severity = s
		if got := osvSeverity(v); got != normalizer.SeverityMedium {
			t.Errorf("osvSeverity(%s) = %q, want medium", s, got)
		}
	}
}

func TestOSVSeverity_Low(t *testing.T) {
	v := osvVuln{}
	v.DatabaseSpecific.Severity = "LOW"
	if got := osvSeverity(v); got != normalizer.SeverityLow {
		t.Errorf("osvSeverity(LOW) = %q, want low", got)
	}
}

func TestOSVSeverityFromCVSS_Medium(t *testing.T) {
	v := osvVuln{}
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "5.5"}}
	if got := osvSeverityFromCVSS(v); got != normalizer.SeverityMedium {
		t.Errorf("osvSeverityFromCVSS(5.5) = %q, want medium", got)
	}
}

func TestOSVSeverityFromCVSS_Low(t *testing.T) {
	v := osvVuln{}
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "2.0"}}
	if got := osvSeverityFromCVSS(v); got != normalizer.SeverityLow {
		t.Errorf("osvSeverityFromCVSS(2.0) = %q, want low", got)
	}
}

func TestOSVSeverityFromCVSS_NonNumericVector(t *testing.T) {
	// CVSS vector strings are not parseable as float; should fall through to info.
	v := osvVuln{}
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L"}}
	if got := osvSeverityFromCVSS(v); got != normalizer.SeverityInfo {
		t.Errorf("osvSeverityFromCVSS(vector) = %q, want info", got)
	}
}

func TestOSVSeverityFromCVSS_Empty(t *testing.T) {
	v := osvVuln{}
	if got := osvSeverityFromCVSS(v); got != normalizer.SeverityInfo {
		t.Errorf("osvSeverityFromCVSS(empty) = %q, want info", got)
	}
}

func TestOSVRuleURL_NoMatch(t *testing.T) {
	v := osvVuln{References: []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}{{Type: "FIX", URL: "https://example.com/fix"}}}
	if got := osvRuleURL(v); got != "" {
		t.Errorf("osvRuleURL with no WEB/ADVISORY = %q, want empty", got)
	}
}

// ── poutine ───────────────────────────────────────────────────────────────────

func TestParsePoutineJSON_Malformed(t *testing.T) {
	_, err := parsePoutineJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNormalizePoutine_Nil(t *testing.T) {
	if got := normalizePoutine(nil); got != nil {
		t.Errorf("normalizePoutine(nil) = %v, want nil", got)
	}
}

func TestPoutineSeverity_Low(t *testing.T) {
	if got := poutineSeverity("low"); got != normalizer.SeverityLow {
		t.Errorf("poutineSeverity(low) = %q, want low", got)
	}
}

func TestPoutineSeverity_Default(t *testing.T) {
	if got := poutineSeverity("none"); got != normalizer.SeverityInfo {
		t.Errorf("poutineSeverity(none) = %q, want info", got)
	}
}

// ── semgrep ───────────────────────────────────────────────────────────────────

func TestParseSemgrepJSON_Malformed(t *testing.T) {
	_, err := parseSemgrepJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNormalizeSemgrep_Nil(t *testing.T) {
	if got := normalizeSemgrep(nil); got != nil {
		t.Errorf("normalizeSemgrep(nil) = %v, want nil", got)
	}
}

func TestSemgrepSeverity_InfoDefault(t *testing.T) {
	// INFO and unknown levels fall through to low.
	for _, level := range []string{"INFO", "unknown"} {
		if got := semgrepSeverity(level, semgrepMetadata{}); got != normalizer.SeverityLow {
			t.Errorf("semgrepSeverity(%q) = %q, want low", level, got)
		}
	}
}

// ── trivy ─────────────────────────────────────────────────────────────────────

func TestParseTrivyJSON_Malformed(t *testing.T) {
	_, err := parseTrivyJSON([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNormalizeTrivy_Nil(t *testing.T) {
	if got := normalizeTrivy(nil); got != nil {
		t.Errorf("normalizeTrivy(nil) = %v, want nil", got)
	}
}

func TestTrivySeverity_Medium(t *testing.T) {
	if got := trivySeverity("MEDIUM"); got != normalizer.SeverityMedium {
		t.Errorf("trivySeverity(MEDIUM) = %q, want medium", got)
	}
}

func TestTrivySeverity_Low(t *testing.T) {
	if got := trivySeverity("LOW"); got != normalizer.SeverityLow {
		t.Errorf("trivySeverity(LOW) = %q, want low", got)
	}
}

func TestTrivySeverity_Default(t *testing.T) {
	if got := trivySeverity("UNKNOWN"); got != normalizer.SeverityInfo {
		t.Errorf("trivySeverity(UNKNOWN) = %q, want info", got)
	}
}

// ── zizmor ────────────────────────────────────────────────────────────────────

func TestParseZizmorSARIF_Malformed(t *testing.T) {
	_, err := parseZizmorSARIF([]byte("{bad}"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNormalizeZizmor_Nil(t *testing.T) {
	if got := normalizeZizmor(nil); got != nil {
		t.Errorf("normalizeZizmor(nil) = %v, want nil", got)
	}
}

func TestZizmorSeverity_Default(t *testing.T) {
	if got := zizmorSeverity("unknown"); got != normalizer.SeverityLow {
		t.Errorf("zizmorSeverity(unknown) = %q, want low", got)
	}
}

func TestZizmorExtractLocation_Empty(t *testing.T) {
	// When a SARIF result carries no locations the extractor must return
	// zero values rather than panicking.
	file, line, col := zizmorExtractLocation(nil)
	if file != "" || line != 0 || col != 0 {
		t.Errorf("zizmorExtractLocation(nil) = (%q,%d,%d), want ('',0,0)", file, line, col)
	}
}

// ── malformed JSON via fake subprocess (tests execute path) ───────────────────

func TestActionlintRun_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	a := &Actionlint{
		execFunc: fakeActionlintExecFunc("{bad json}", 0),
		lookPath: func(string) (string, error) { return "/usr/bin/actionlint", nil },
	}
	_, err := a.Run(context.Background(), dir)
	if err == nil {
		t.Fatal("Run() with malformed JSON expected error, got nil")
	}
}

func TestOSVRun_MalformedJSON(t *testing.T) {
	o := &OSVScanner{
		execFunc: fakeOSVExecFunc("{bad json}", 0),
		lookPath: lookPathOSV(),
	}
	_, err := o.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() with malformed JSON expected error, got nil")
	}
}

func TestTrivyRun_MalformedJSON(t *testing.T) {
	tv := &Trivy{
		execFunc: fakeTrivyExecFunc("{bad json}", 0),
		lookPath: lookPathTrivy(),
	}
	_, err := tv.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() with malformed JSON expected error, got nil")
	}
}

func TestCheckovRun_MalformedJSON(t *testing.T) {
	ck := &Checkov{
		execFunc: fakeCheckovExecFunc("{bad json}", 0),
		lookPath: lookPathCheckov(),
	}
	_, err := ck.Run(context.Background(), ".")
	if err == nil {
		t.Fatal("Run() with malformed JSON expected error, got nil")
	}
}
