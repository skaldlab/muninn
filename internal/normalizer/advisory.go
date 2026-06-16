package normalizer

import "strings"

// advisoryPrefixes are the identifier schemes for published vulnerability
// advisories that scanners report. An identifier with one of these prefixes is
// treated as a real advisory (and therefore deduplicatable across scanners),
// while anything else (e.g. "generic-api-key") is a scanner-internal rule name.
var advisoryPrefixes = []string{
	"CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-",
	"OSV-", "DSA-", "DLA-", "USN-", "ALSA-", "ALAS-", "SNYK-",
}

// AdvisoryID returns the published vulnerability advisory identifier a finding
// represents, or "" when the finding is not a known-advisory vulnerability
// (a secret, SAST, or IaC finding, for example). A CVE is preferred over GHSA
// and the ecosystem-specific schemes because it is the identifier scanners most
// often share, so the same vulnerability reported by different scanners resolves
// to one id. This is the key used to deduplicate findings across scanners.
func AdvisoryID(f Finding) string {
	ids := advisoryCandidates(f)
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			return strings.ToUpper(id)
		}
	}
	for _, id := range ids {
		if isAdvisoryID(id) {
			return id
		}
	}
	return ""
}

// advisoryCandidates gathers the identifiers that might name this finding's
// advisory: its native rule id plus any cross-references the scanner recorded
// in metadata["aliases"].
func advisoryCandidates(f Finding) []string {
	var ids []string
	if f.RuleID != "" {
		ids = append(ids, f.RuleID)
	}
	return append(ids, metaStringSlice(f.Metadata, "aliases")...)
}

// isAdvisoryID reports whether id carries one of the known advisory prefixes.
func isAdvisoryID(id string) bool {
	up := strings.ToUpper(id)
	for _, p := range advisoryPrefixes {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	return false
}

// PackageName returns the affected package name from the metadata keys the
// dependency scanners use (osv-scanner: package; trivy: pkg_name), or "".
func PackageName(f Finding) string {
	return metaString(f.Metadata, "package", "pkg_name")
}

// PackageVersion returns the affected package version (osv-scanner: version;
// trivy: installed_version), or "".
func PackageVersion(f Finding) string {
	return metaString(f.Metadata, "version", "installed_version")
}

// Ecosystem returns the package ecosystem (e.g. "npm", "PyPI") when a scanner
// records it (osv-scanner), or "".
func Ecosystem(f Finding) string {
	return metaString(f.Metadata, "ecosystem")
}

// InjectionSources returns untrusted GitHub Actions context paths that poutine
// recorded for an injection finding, or nil when absent.
func InjectionSources(f Finding) []string {
	return metaStringSlice(f.Metadata, "injection_sources")
}

// metaString returns the first metadata value among keys that is a non-empty
// string, or "" when none match.
func metaString(meta map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := meta[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// metaStringSlice extracts a metadata value that is a list of strings, tolerating
// both the native []string and the []any shape a JSON round-trip would produce.
func metaStringSlice(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
