# Changelog

## [Unreleased]

### Added
- Keyless (OIDC) cosign signing of the published container image and of the
  release binary checksums (`checksums.txt.sig` / `checksums.txt.pem`)
- SBOM (SPDX) attached to every release and as an image attestation
- Max-mode SLSA build provenance attestation on the container image
- "Verifying releases" instructions in the README

## [0.1.0] - 2026-06-14

### Added
- 8 security scanners: gitleaks, zizmor, actionlint, poutine,
  semgrep, osv-scanner, trivy, checkov
- Unified Finding schema with fingerprinting
- Three output formats: SARIF 2.1.0, JSON, GitHub PR comment
- GitHub Action with outputs
- Config-driven scanner behavior via muninn.yml
- Suppression management with expiry dates
- 90%+ test coverage enforced in CI
- Integration tests with real scanner binaries
- Self-scan: Muninn scans itself on every PR

Built by Skald Lab — skaldlab.dev
