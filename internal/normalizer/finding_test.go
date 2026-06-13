package normalizer

import (
	"encoding/json"
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	cases := []struct {
		got  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Errorf("Severity constant = %q, want %q", tc.got, tc.want)
		}
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	original := Finding{
		ID:          "fp001",
		Tool:        "gitleaks",
		Severity:    SeverityHigh,
		Title:       "Exposed AWS key",
		Description: "AWS access key found in source code",
		File:        "config/secrets.go",
		Line:        42,
		Column:      7,
		RuleID:      "aws-access-key",
		RuleURL:     "https://example.com/rule",
		Fingerprint: "fp001",
		Suppressed:  false,
		Metadata:    map[string]any{"commit": "abc123"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ID != original.ID {
		t.Errorf("ID: got %q, want %q", got.ID, original.ID)
	}
	if got.Tool != original.Tool {
		t.Errorf("Tool: got %q, want %q", got.Tool, original.Tool)
	}
	if got.Severity != original.Severity {
		t.Errorf("Severity: got %q, want %q", got.Severity, original.Severity)
	}
	if got.Title != original.Title {
		t.Errorf("Title: got %q, want %q", got.Title, original.Title)
	}
	if got.File != original.File {
		t.Errorf("File: got %q, want %q", got.File, original.File)
	}
	if got.Line != original.Line {
		t.Errorf("Line: got %d, want %d", got.Line, original.Line)
	}
	if got.Column != original.Column {
		t.Errorf("Column: got %d, want %d", got.Column, original.Column)
	}
	if got.RuleID != original.RuleID {
		t.Errorf("RuleID: got %q, want %q", got.RuleID, original.RuleID)
	}
	if got.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint: got %q, want %q", got.Fingerprint, original.Fingerprint)
	}
}

func TestFindingOmitEmptyFields(t *testing.T) {
	// Column, RuleURL, and Metadata are tagged omitempty — they must be absent
	// in JSON output when zero-valued, keeping the schema clean for consumers.
	f := Finding{
		ID:       "x",
		Tool:     "test",
		Severity: SeverityInfo,
		Title:    "t",
		File:     "f.go",
		Line:     1,
		RuleID:   "rule",
		// Column, RuleURL, Metadata intentionally zero
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, absent := range []string{`"column"`, `"rule_url"`, `"metadata"`} {
		// json.Marshal omits omitempty fields when zero
		if contains(s, absent) {
			t.Errorf("JSON should not contain %s when zero, got: %s", absent, s)
		}
	}
}

func TestFindingSuppressed(t *testing.T) {
	f := Finding{Suppressed: true}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.Suppressed {
		t.Error("Suppressed should round-trip as true")
	}
}

// contains is a simple substring helper to avoid importing strings in tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
