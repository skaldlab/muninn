package scanner

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/skaldlab/muninn/internal/config"
)

// captureExecFunc returns an execFunc that captures the args passed to the
// subprocess while still running the scanner fake to produce valid output.
// It uses the same MUNINN_FAKE_* pattern as other scanner tests so that
// TestMain dispatches to the right fake binary handler.
func captureExecFunc(t *testing.T, captured *[]string, fakeEnvKey, jsonStr string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	t.Helper()
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		*captured = append([]string{}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Args = append([]string{os.Args[0]}, args...)
		cmd.Env = append(os.Environ(),
			fakeEnvKey+"=1",
			"MUNINN_FAKE_STDOUT="+jsonStr,
			"MUNINN_FAKE_EXIT="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// containsPair reports whether args contains two consecutive elements key, val.
func containsPair(args []string, key, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == val {
			return true
		}
	}
	return false
}

// containsFlag reports whether args contains the given flag anywhere.
func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// ── Semgrep ───────────────────────────────────────────────────────────────────

func TestConfigureSemgrep_Rulesets(t *testing.T) {
	var capturedArgs []string
	s := &Semgrep{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_SEMGREP", `{"results":[]}`, 0),
		lookPath: lookPathSemgrep(),
	}

	s.Configure(config.ScannerConfig{
		Rulesets: []string{"p/custom-rules", "p/owasp-top-ten"},
	})

	if _, err := s.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsPair(capturedArgs, "--config", "p/custom-rules") {
		t.Errorf("args missing --config p/custom-rules; got %v", capturedArgs)
	}
	if !containsPair(capturedArgs, "--config", "p/owasp-top-ten") {
		t.Errorf("args missing --config p/owasp-top-ten; got %v", capturedArgs)
	}
	// Default ruleset must not appear when overridden.
	if containsPair(capturedArgs, "--config", "p/security-audit") {
		t.Errorf("args should not contain default p/security-audit when rulesets are overridden; got %v", capturedArgs)
	}
}

func TestConfigureSemgrep_ExcludePaths(t *testing.T) {
	var capturedArgs []string
	s := &Semgrep{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_SEMGREP", `{"results":[]}`, 0),
		lookPath: lookPathSemgrep(),
	}

	s.Configure(config.ScannerConfig{
		ExcludePaths: []string{"vendor/", "node_modules/"},
	})

	if _, err := s.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsPair(capturedArgs, "--exclude", "vendor/") {
		t.Errorf("args missing --exclude vendor/; got %v", capturedArgs)
	}
	if !containsPair(capturedArgs, "--exclude", "node_modules/") {
		t.Errorf("args missing --exclude node_modules/; got %v", capturedArgs)
	}
}

func TestConfigureSemgrep_DefaultRulesetsWhenNoneConfigured(t *testing.T) {
	var capturedArgs []string
	s := &Semgrep{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_SEMGREP", `{"results":[]}`, 0),
		lookPath: lookPathSemgrep(),
	}

	// No rulesets configured — defaults should be used.
	s.Configure(config.ScannerConfig{})

	if _, err := s.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsPair(capturedArgs, "--config", "p/security-audit") {
		t.Errorf("args missing default --config p/security-audit; got %v", capturedArgs)
	}
	if !containsPair(capturedArgs, "--config", "p/secrets") {
		t.Errorf("args missing default --config p/secrets; got %v", capturedArgs)
	}
}

// ── Trivy ─────────────────────────────────────────────────────────────────────

func TestConfigureTrivy_Severity(t *testing.T) {
	var capturedArgs []string
	tv := &Trivy{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_TRIVY", `{"Results":[]}`, 0),
		lookPath: lookPathTrivy(),
	}

	tv.Configure(config.ScannerConfig{
		Severity: []string{"CRITICAL"},
	})

	if _, err := tv.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsPair(capturedArgs, "--severity", "CRITICAL") {
		t.Errorf("args missing --severity CRITICAL; got %v", capturedArgs)
	}
	// HIGH must not appear when it's not in the configured severity list.
	if containsPair(capturedArgs, "--severity", "HIGH,CRITICAL") {
		t.Errorf("args should not contain default HIGH,CRITICAL; got %v", capturedArgs)
	}
}

func TestConfigureTrivy_IgnoreUnfixed(t *testing.T) {
	var capturedArgs []string
	tv := &Trivy{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_TRIVY", `{"Results":[]}`, 0),
		lookPath: lookPathTrivy(),
	}

	tv.Configure(config.ScannerConfig{
		IgnoreUnfixed: true,
	})

	if _, err := tv.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsFlag(capturedArgs, "--ignore-unfixed") {
		t.Errorf("args missing --ignore-unfixed; got %v", capturedArgs)
	}
}

func TestConfigureTrivy_IgnoreUnfixedFalse(t *testing.T) {
	var capturedArgs []string
	tv := &Trivy{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_TRIVY", `{"Results":[]}`, 0),
		lookPath: lookPathTrivy(),
	}

	tv.Configure(config.ScannerConfig{
		IgnoreUnfixed: false,
	})

	if _, err := tv.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if containsFlag(capturedArgs, "--ignore-unfixed") {
		t.Errorf("args should not contain --ignore-unfixed when disabled; got %v", capturedArgs)
	}
}

// ── Checkov ───────────────────────────────────────────────────────────────────

func TestConfigureCheckov_SkipChecks(t *testing.T) {
	var capturedArgs []string
	c := &Checkov{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_CHECKOV", `[]`, 0),
		lookPath: lookPathCheckov(),
	}

	c.Configure(config.ScannerConfig{
		SkipChecks: []string{"CKV_AWS_18", "CKV_AWS_20"},
	})

	if _, err := c.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !containsPair(capturedArgs, "--skip-check", "CKV_AWS_18") {
		t.Errorf("args missing --skip-check CKV_AWS_18; got %v", capturedArgs)
	}
	if !containsPair(capturedArgs, "--skip-check", "CKV_AWS_20") {
		t.Errorf("args missing --skip-check CKV_AWS_20; got %v", capturedArgs)
	}
}

func TestConfigureCheckov_NoSkipChecks(t *testing.T) {
	var capturedArgs []string
	c := &Checkov{
		execFunc: captureExecFunc(t, &capturedArgs, "MUNINN_FAKE_CHECKOV", `[]`, 0),
		lookPath: lookPathCheckov(),
	}

	c.Configure(config.ScannerConfig{})

	if _, err := c.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if containsFlag(capturedArgs, "--skip-check") {
		t.Errorf("args should not contain --skip-check when none configured; got %v", capturedArgs)
	}
}
