// Package config handles loading and validating the muninn.yml configuration file.
// The zero value of Config is not valid; always use Load to obtain a Config.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure for muninn.yml.
type Config struct {
	// Version must be 1. Reserved for future breaking-change migrations.
	Version int `yaml:"version"`

	// FailOn is the minimum severity that causes Muninn to exit non-zero.
	// Accepted values: critical, high, medium, low.
	FailOn string `yaml:"fail-on"`

	// Scanners maps each scanner name to its individual configuration.
	Scanners map[string]ScannerConfig `yaml:"scanners"`

	// Suppressions is the list of rules used to mark findings as suppressed
	// before they reach the fail-on evaluation.
	Suppressions []Suppression `yaml:"-"`
}

// ScannerConfig holds the per-scanner options defined in muninn.yml.
// Fields that are not applicable to a scanner are silently ignored.
type ScannerConfig struct {
	// Enabled controls whether the scanner runs. Defaults to true.
	Enabled bool `yaml:"enabled"`

	// Rulesets is used by semgrep to select rule packs (e.g. "p/security-audit").
	Rulesets []string `yaml:"rulesets"`

	// ExcludePaths is a list of path prefixes to skip during scanning.
	ExcludePaths []string `yaml:"exclude-paths"`

	// Severity is used by trivy to filter by severity level (e.g. ["CRITICAL","HIGH"]).
	Severity []string `yaml:"severity"`

	// IgnoreUnfixed tells trivy to omit vulnerabilities that have no fix available.
	IgnoreUnfixed bool `yaml:"ignore-unfixed"`

	// SkipChecks is used by checkov to suppress specific check IDs.
	SkipChecks []string `yaml:"skip-checks"`
}

// Suppression describes a rule for silencing a specific finding.
type Suppression struct {
	// ID suppresses findings whose file path contains this prefix (e.g. a fixture dir).
	ID string `yaml:"id,omitempty"`

	// Tool is the scanner name the suppression applies to.
	Tool string `yaml:"tool,omitempty"`

	// RuleID is the scanner-native rule identifier to suppress.
	RuleID string `yaml:"rule-id,omitempty"`

	// Reason is a required human-readable explanation for the suppression.
	Reason string `yaml:"reason"`

	// Fingerprint is the finding fingerprint to suppress.
	Fingerprint string `yaml:"fingerprint,omitempty"`

	// Expires is the UTC time after which this suppression is no longer active.
	// The zero value means the suppression never expires.
	Expires time.Time `yaml:"-"`
}

// suppressionYAML is the on-disk shape for a suppression entry. Expires is a
// string so empty values in muninn.yml parse as "never expires".
type suppressionYAML struct {
	ID          string `yaml:"id,omitempty"`
	Tool        string `yaml:"tool,omitempty"`
	RuleID      string `yaml:"rule-id,omitempty"`
	Reason      string `yaml:"reason"`
	Fingerprint string `yaml:"fingerprint,omitempty"`
	Expires     string `yaml:"expires,omitempty"`
}

// configYAML is the on-disk shape for muninn.yml.
type configYAML struct {
	Version      int                      `yaml:"version"`
	FailOn       string                   `yaml:"fail-on"`
	Scanners     map[string]ScannerConfig `yaml:"scanners"`
	Suppressions []suppressionYAML        `yaml:"suppressions"`
}

// Load reads and parses the muninn.yml file at path.
// It returns an error if the file cannot be read or parsed.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	cfg := Defaults()
	if len(data) > 0 {
		var file configYAML
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parsing config file %q: %w", path, err)
		}
		if err := applyConfigFile(cfg, file); err != nil {
			return nil, fmt.Errorf("parsing config file %q: %w", path, err)
		}
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// applyConfigFile merges parsed muninn.yml fields into cfg.
func applyConfigFile(cfg *Config, file configYAML) error {
	if file.Version != 0 {
		cfg.Version = file.Version
	}
	if file.FailOn != "" {
		cfg.FailOn = file.FailOn
	}
	if file.Scanners != nil {
		cfg.Scanners = file.Scanners
	}
	suppressions, err := parseSuppressions(file.Suppressions)
	if err != nil {
		return err
	}
	if suppressions != nil {
		cfg.Suppressions = suppressions
	}
	return nil
}

// parseSuppressions converts YAML suppression entries to Config suppressions.
func parseSuppressions(raw []suppressionYAML) ([]Suppression, error) {
	if raw == nil {
		return nil, nil
	}
	out := make([]Suppression, 0, len(raw))
	for _, s := range raw {
		item := Suppression{
			ID:          s.ID,
			Tool:        s.Tool,
			RuleID:      s.RuleID,
			Reason:      s.Reason,
			Fingerprint: s.Fingerprint,
		}
		if s.Expires != "" {
			expires, err := time.Parse(time.RFC3339, s.Expires)
			if err != nil {
				return nil, fmt.Errorf("parsing suppression expires %q: %w", s.Expires, err)
			}
			item.Expires = expires
		}
		out = append(out, item)
	}
	return out, nil
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
		"info":     true,
	}
	if cfg.FailOn != "" && !validSeverities[cfg.FailOn] {
		return fmt.Errorf("invalid fail-on value %q; must be one of: critical, high, medium, low, info", cfg.FailOn)
	}

	for i, s := range cfg.Suppressions {
		if !suppressionHasSelector(s) {
			return fmt.Errorf("suppression %d: must specify id, fingerprint, tool, and/or rule-id", i+1)
		}
	}

	return nil
}

// suppressionHasSelector reports whether a suppression entry specifies at least
// one matching criterion.
func suppressionHasSelector(s Suppression) bool {
	return s.ID != "" || s.Fingerprint != "" || s.Tool != "" || s.RuleID != ""
}
