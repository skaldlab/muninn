package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_FullFileWithSuppressions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	content := []byte(`version: 1
fail-on: high
scanners:
  gitleaks:
    enabled: true
suppressions:
  - tool: gitleaks
    rule-id: aws-key
    reason: fixture
    expires: "2099-01-02T15:04:05Z"
  - id: testdata/
    fingerprint: abc
    reason: fixtures
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FailOn != "high" {
		t.Errorf("FailOn = %q, want high", cfg.FailOn)
	}
	if !cfg.ConfiguredScanners["gitleaks"] {
		t.Error("ConfiguredScanners missing gitleaks")
	}
	if len(cfg.Suppressions) != 2 {
		t.Fatalf("Suppressions = %d, want 2", len(cfg.Suppressions))
	}
	if cfg.Suppressions[0].Tool != "gitleaks" || cfg.Suppressions[0].RuleID != "aws-key" {
		t.Errorf("first suppression = %+v", cfg.Suppressions[0])
	}
	wantExpiry := time.Date(2099, 1, 2, 15, 4, 5, 0, time.UTC)
	if !cfg.Suppressions[0].Expires.Equal(wantExpiry) {
		t.Errorf("Expires = %v, want %v", cfg.Suppressions[0].Expires, wantExpiry)
	}
	if cfg.Suppressions[1].ID != "testdata/" || cfg.Suppressions[1].Fingerprint != "abc" {
		t.Errorf("second suppression = %+v", cfg.Suppressions[1])
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	if err := os.WriteFile(path, []byte("version: [\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load expected YAML parse error")
	}
}

func TestLoad_InvalidExpires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	content := []byte(`version: 1
suppressions:
  - tool: gitleaks
    reason: bad date
    expires: not-a-date
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load expected expires parse error")
	}
}

func TestLoad_InvalidFailOn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	if err := os.WriteFile(path, []byte("version: 1\nfail-on: nope\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load expected invalid fail-on error")
	}
}

func TestLoad_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	if err := os.WriteFile(path, []byte("version: 99\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load expected unsupported version error")
	}
}

func TestParseSuppressions_NilAndEmpty(t *testing.T) {
	got, err := parseSuppressions(nil)
	if err != nil || got != nil {
		t.Fatalf("nil raw = (%v, %v), want (nil, nil)", got, err)
	}
	got, err = parseSuppressions([]suppressionYAML{})
	if err != nil {
		t.Fatalf("empty raw: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty raw len = %d, want 0", len(got))
	}
}

func TestApplyBitbucketScannerDefaults_NilAndEmpty(t *testing.T) {
	ApplyBitbucketScannerDefaults(nil) // must not panic

	cfg := &Config{}
	ApplyBitbucketScannerDefaults(cfg)
	if cfg.Scanners == nil {
		t.Fatal("Scanners map should be initialized")
	}
	for _, name := range []string{"zizmor", "actionlint", "poutine"} {
		if cfg.Scanners[name].Enabled {
			t.Errorf("%s should be disabled", name)
		}
	}
	if !cfg.Scanners["pipeline-check"].Enabled {
		t.Error("pipeline-check should be enabled")
	}
}

func TestSuppressionHasSelector(t *testing.T) {
	cases := []struct {
		s    Suppression
		want bool
	}{
		{Suppression{}, false},
		{Suppression{ID: "x"}, true},
		{Suppression{Fingerprint: "f"}, true},
		{Suppression{Tool: "t"}, true},
		{Suppression{RuleID: "r"}, true},
	}
	for _, tc := range cases {
		if got := suppressionHasSelector(tc.s); got != tc.want {
			t.Errorf("suppressionHasSelector(%+v) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
