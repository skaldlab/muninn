package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.FailOn != "critical" {
		t.Errorf("FailOn = %q, want critical", cfg.FailOn)
	}

	want := []string{"gitleaks", "semgrep", "zizmor", "actionlint", "poutine", "trivy", "osv-scanner", "checkov"}
	for _, name := range want {
		sc, ok := cfg.Scanners[name]
		if !ok {
			t.Errorf("Scanners[%q] missing", name)
			continue
		}
		if !sc.Enabled {
			t.Errorf("Scanners[%q].Enabled = false, want true", name)
		}
	}

	// Semgrep ships with default rulesets.
	if len(cfg.Scanners["semgrep"].Rulesets) == 0 {
		t.Error("semgrep rulesets should not be empty")
	}
	// Trivy ships with severity filter and ignore-unfixed.
	trivy := cfg.Scanners["trivy"]
	if len(trivy.Severity) == 0 {
		t.Error("trivy severity filter should not be empty")
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
	for _, failOn := range []string{"critical", "high", "medium", "low", ""} {
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
