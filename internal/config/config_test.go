package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.FailOn != "info" {
		t.Errorf("FailOn = %q, want info", cfg.FailOn)
	}

	wantEnabled := []string{"gitleaks", "semgrep", "zizmor", "actionlint", "poutine", "trivy", "osv-scanner", "checkov", "skillspector"}
	for _, name := range wantEnabled {
		sc, ok := cfg.Scanners[name]
		if !ok {
			t.Errorf("Scanners[%q] missing", name)
			continue
		}
		if !sc.Enabled {
			t.Errorf("Scanners[%q].Enabled = false, want true", name)
		}
	}
	pc, ok := cfg.Scanners["pipeline-check"]
	if !ok {
		t.Fatal("Scanners[pipeline-check] missing")
	}
	if pc.Enabled {
		t.Error("pipeline-check should default to disabled outside Bitbucket CI")
	}

	// Semgrep ships with default rulesets.
	if len(cfg.Scanners["semgrep"].Rulesets) == 0 {
		t.Error("semgrep rulesets should not be empty")
	}
	// Trivy ships with all severity levels and ignore-unfixed by default.
	trivy := cfg.Scanners["trivy"]
	wantSev := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if len(trivy.Severity) != len(wantSev) {
		t.Fatalf("trivy.Severity = %v, want %v", trivy.Severity, wantSev)
	}
	for i, s := range wantSev {
		if trivy.Severity[i] != s {
			t.Errorf("trivy.Severity[%d] = %q, want %q", i, trivy.Severity[i], s)
		}
	}
	if !trivy.IgnoreUnfixed {
		t.Error("trivy IgnoreUnfixed should be true by default")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/muninn.yml")
	if err == nil {
		t.Fatal("Load() with missing file expected error, got nil")
	}
}

func TestLoad_ExistingFile(t *testing.T) {
	// Current implementation reads the file but returns Defaults() (YAML parsing is TODO).
	// Any readable file should produce defaults and no error.
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	if err := os.WriteFile(path, []byte("version: 1\nfail_on: high\n"), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	// Stub returns Defaults(), so version should be 1.
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	// An empty file is readable; the stub returns Defaults().
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error for empty file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
}

func TestValidate_ValidVersionAndFailOn(t *testing.T) {
	for _, failOn := range []string{"critical", "high", "medium", "low", "info", ""} {
		cfg := &Config{Version: 1, FailOn: failOn}
		if err := validate(cfg); err != nil {
			t.Errorf("validate with FailOn=%q expected nil, got %v", failOn, err)
		}
	}
}

func TestValidate_BadVersion(t *testing.T) {
	cfg := &Config{Version: 2, FailOn: "critical"}
	if err := validate(cfg); err == nil {
		t.Error("validate with version 2 expected error, got nil")
	}
}

func TestValidate_InvalidFailOn(t *testing.T) {
	cfg := &Config{Version: 1, FailOn: "unknown"}
	if err := validate(cfg); err == nil {
		t.Error("validate with fail-on=unknown expected error, got nil")
	}
}

func TestScannerConfigFields(t *testing.T) {
	sc := ScannerConfig{
		Enabled:       true,
		Rulesets:      []string{"p/security-audit"},
		ExcludePaths:  []string{"vendor/"},
		Severity:      []string{"CRITICAL"},
		IgnoreUnfixed: true,
		SkipChecks:    []string{"CKV_AWS_18"},
	}
	if !sc.Enabled {
		t.Error("Enabled should be true")
	}
	if len(sc.Rulesets) != 1 {
		t.Error("Rulesets length mismatch")
	}
}

func TestSuppressionFields(t *testing.T) {
	s := Suppression{
		Tool:   "gitleaks",
		RuleID: "aws-access-key",
		Reason: "test credential",
	}
	if s.Tool != "gitleaks" {
		t.Errorf("Tool = %q", s.Tool)
	}
	if s.RuleID != "aws-access-key" {
		t.Errorf("RuleID = %q", s.RuleID)
	}
}

func TestValidate_SuppressionRequiresSelector(t *testing.T) {
	cfg := Defaults()
	cfg.Suppressions = []Suppression{
		{Reason: "no matcher fields"},
	}
	if err := validate(cfg); err == nil {
		t.Fatal("validate expected error for suppression without selectors, got nil")
	}
}

func TestValidate_SuppressionToolOnlyAccepted(t *testing.T) {
	cfg := Defaults()
	cfg.Suppressions = []Suppression{
		{Tool: "poutine", Reason: "mute scanner"},
	}
	if err := validate(cfg); err != nil {
		t.Fatalf("validate with tool-only suppression: %v", err)
	}
}

func TestApplyBitbucketScannerDefaults_DisablesGitHubScanners(t *testing.T) {
	cfg := Defaults()
	ApplyBitbucketScannerDefaults(cfg)
	for _, name := range []string{"zizmor", "actionlint", "poutine"} {
		if cfg.Scanners[name].Enabled {
			t.Errorf("%s should be disabled on Bitbucket by default", name)
		}
	}
	if !cfg.Scanners["gitleaks"].Enabled {
		t.Error("gitleaks should remain enabled")
	}
	if !cfg.Scanners["pipeline-check"].Enabled {
		t.Error("pipeline-check should be enabled on Bitbucket by default")
	}
}

func TestApplyBitbucketScannerDefaults_ExplicitEnabledWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	content := []byte(`version: 1
scanners:
  zizmor:
    enabled: true
  actionlint:
    enabled: false
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ApplyBitbucketScannerDefaults(cfg)
	if !cfg.Scanners["zizmor"].Enabled {
		t.Error("explicit zizmor enabled: true must win")
	}
	if cfg.Scanners["actionlint"].Enabled {
		t.Error("explicit actionlint enabled: false must stay false")
	}
	if cfg.Scanners["poutine"].Enabled {
		t.Error("poutine omitted from file should be disabled on Bitbucket")
	}
	if !cfg.Scanners["pipeline-check"].Enabled {
		t.Error("pipeline-check omitted from file should be enabled on Bitbucket")
	}
}

func TestApplyBitbucketScannerDefaults_ExplicitPipelineCheckOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "muninn.yml")
	content := []byte(`version: 1
scanners:
  pipeline-check:
    enabled: false
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ApplyBitbucketScannerDefaults(cfg)
	if cfg.Scanners["pipeline-check"].Enabled {
		t.Error("explicit pipeline-check enabled: false must win")
	}
}

func TestApplyBitbucketScannerDefaults_PreservesOptionsAndIsIdempotent(t *testing.T) {
	cfg := Defaults()
	cfg.Scanners["zizmor"] = ScannerConfig{Enabled: true, ExcludePaths: []string{"fixtures/"}}
	cfg.Scanners["pipeline-check"] = ScannerConfig{Enabled: false, ExcludePaths: []string{"vendor/"}}
	cfg.Scanners["poutine"] = ScannerConfig{Enabled: false}
	cfg.ConfiguredScanners = map[string]bool{"poutine": true, "actionlint": true}
	cfg.Scanners["actionlint"] = ScannerConfig{Enabled: true}
	unrelated := cfg.Scanners["semgrep"]
	ApplyBitbucketScannerDefaults(cfg)
	if cfg.Scanners["zizmor"].Enabled || !cfg.Scanners["pipeline-check"].Enabled {
		t.Error("Bitbucket defaults were not applied")
	}
	if !reflect.DeepEqual(cfg.Scanners["zizmor"].ExcludePaths, []string{"fixtures/"}) || !reflect.DeepEqual(cfg.Scanners["pipeline-check"].ExcludePaths, []string{"vendor/"}) {
		t.Error("scanner options were lost")
	}
	if cfg.Scanners["poutine"].Enabled || !cfg.Scanners["actionlint"].Enabled {
		t.Error("explicit scanner choices were overwritten")
	}
	if !reflect.DeepEqual(cfg.Scanners["semgrep"], unrelated) {
		t.Error("unrelated scanner was modified")
	}
	before := make(map[string]ScannerConfig, len(cfg.Scanners))
	for name, sc := range cfg.Scanners {
		before[name] = sc
	}
	ApplyBitbucketScannerDefaults(cfg)
	if !reflect.DeepEqual(cfg.Scanners, before) {
		t.Error("reapplying defaults changed scanner configuration")
	}
	if !reflect.DeepEqual(cfg.ConfiguredScanners, map[string]bool{"poutine": true, "actionlint": true}) {
		t.Error("configured scanner tracking was modified")
	}
}
