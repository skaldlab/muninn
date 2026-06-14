// Package config handles loading and validating the muninn.yml configuration file.
// The zero value of Config is not valid; always use Load to obtain a Config.
//
// YAML parsing is intentionally deferred to the first scanner implementation
// that needs it; for now Load reads the file and validates it exists.
// When gopkg.in/yaml.v3 is added as a dependency, replace the stub below.
package config

import (
	"fmt"
	"os"
	"time"
)

// Config is the top-level structure for muninn.yml.
type Config struct {
	// Version must be 1. Reserved for future breaking-change migrations.
	Version int

	// FailOn is the minimum severity that causes Muninn to exit non-zero.
	// Accepted values: critical, high, medium, low.
	FailOn string

	// Scanners maps each scanner name to its individual configuration.
	Scanners map[string]ScannerConfig

	// Suppressions is the list of rules used to mark findings as suppressed
	// before they reach the fail-on evaluation.
	Suppressions []Suppression
}

// ScannerConfig holds the per-scanner options defined in muninn.yml.
// Fields that are not applicable to a scanner are silently ignored.
type ScannerConfig struct {
	// Enabled controls whether the scanner runs. Defaults to true.
	Enabled bool

	// Rulesets is used by semgrep to select rule packs (e.g. "p/security-audit").
	Rulesets []string

	// ExcludePaths is a list of path prefixes to skip during scanning.
	ExcludePaths []string

	// Severity is used by trivy to filter by severity level (e.g. ["CRITICAL","HIGH"]).
	Severity []string

	// IgnoreUnfixed tells trivy to omit vulnerabilities that have no fix available.
	IgnoreUnfixed bool

	// SkipChecks is used by checkov to suppress specific check IDs.
	SkipChecks []string
}

// Suppression describes a rule for silencing a specific finding.
type Suppression struct {
	// Tool is the scanner name the suppression applies to.
	Tool string

	// RuleID is the scanner-native rule identifier to suppress.
	RuleID string

	// Reason is a required human-readable explanation for the suppression.
	Reason string

	// Fingerprint is the finding fingerprint to suppress. When set it takes
	// precedence over Tool+RuleID matching.
	Fingerprint string

	// Expires is the UTC time after which this suppression is no longer active.
	// The zero value means the suppression never expires.
	Expires time.Time
}

// Load reads and parses the muninn.yml file at path.
// It returns an error if the file cannot be read.
//
// TODO: replace stub with full YAML unmarshaling once gopkg.in/yaml.v3 is added.
func Load(path string) (*Config, error) {
	if _, err := os.ReadFile(path); err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	// Default config returned until YAML parsing is implemented.
	cfg := Defaults()

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Defaults returns a Config pre-populated with the recommended defaults
// from the muninn.yml specification. Callers use this when no config file is
// present rather than operating with a zero-value Config.
func Defaults() *Config {
	enabled := ScannerConfig{Enabled: true}
	return &Config{
		Version: 1,
		FailOn:  "critical",
		Scanners: map[string]ScannerConfig{
			"gitleaks":    enabled,
			"semgrep":     {Enabled: true, Rulesets: []string{"p/security-audit", "p/secrets"}},
			"zizmor":      enabled,
			"actionlint":  enabled,
			"poutine":     enabled,
			"trivy":       {Enabled: true, Severity: []string{"CRITICAL", "HIGH"}, IgnoreUnfixed: true},
			"osv-scanner": enabled,
			"checkov":     enabled,
		},
	}
}

// validate enforces invariants that cannot be expressed in the YAML schema.
func validate(cfg *Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported config version %d; only version 1 is supported", cfg.Version)
	}

	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}
	if cfg.FailOn != "" && !validSeverities[cfg.FailOn] {
		return fmt.Errorf("invalid fail-on value %q; must be one of: critical, high, medium, low", cfg.FailOn)
	}

	return nil
}
