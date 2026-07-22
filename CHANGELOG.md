# Changelog

## [0.3.6] - 2026-07-22

### Changed
- Docker image scanner updates: zizmor 1.28.0 (replaces yanked 1.27.0);
  GitPython floor raised to >=3.1.52 for checkov-transitive GHSA highs
  (checkov remains at 3.2.531 pending aiohttp cap lift).
- Go toolchain bumped to 1.26.5.

## [0.3.5] - 2026-07-20

### Changed
- Docker image scanner updates: semgrep 1.170.0, zizmor 1.27.0 (checkov
  remains at 3.2.531 pending aiohttp cap lift).

## [0.3.4] - 2026-07-04

### Changed
- Docker image scanner updates: osv-scanner 2.4.0, trivy 0.72.0, semgrep
  1.168.0, zizmor 1.26.1 (checkov remains at 3.2.531 pending aiohttp cap lift).

## [0.3.3] - 2026-06-17

### Changed
- Trivy default severity is now all levels (`UNKNOWN` through `CRITICAL`) instead
  of `CRITICAL` and `HIGH` only. osv-scanner and trivy now overlap on
  medium/low advisories by default so cross-scanner dedup and `Detected by`
  work without extra config. Consumers can narrow the Trivy scan with
  `scanners.trivy.severity`; `fail-on` still controls which findings fail the run.

## [0.3.2] - 2026-06-16

### Fixed
- Suppressions with `tool` and/or `rule-id` are now applied. Previously only `id`
  (path substring) and `fingerprint` matchers worked; tool+rule-id entries
  parsed from `muninn.yml` but silently no-op'd.

## [0.3.1] - 2026-06-16

### Fixed
- Poutine v1.x JSON parsing: findings from poutine 1.1.6+ (`rule_id`, `meta`,
  `rules`, `blobshas`) now populate title, rule, and file in PR comments instead
  of empty shells (`File: :0`, `Rule: ``) (#41).
- Actionlint PR comments: fall back to `kind` (e.g. `expression`) when
  `rule.name` is absent; omit empty Rule lines.
- Poutine injection findings: render `injection_sources` as formatted
  **Sources** instead of plain `meta.details` text.

### Changed
- PR comment layout: shared field helpers; non-dependency findings follow
  File → Rule → optional extras → description; single-scanner dependency
  findings use **File** instead of a redundant **Source** line.

## [0.3.0] - 2026-06-16

### Added
- Cross-scanner deduplication by advisory id: findings that report the same
  CVE/GHSA for the same package from different scanners (e.g. OSV-Scanner from a
  lockfile and Trivy from a container layer) are now collapsed into a single
  finding. The contributing scanners are recorded in a new `detected_by` field
  (surfaced in the JSON report, the PR comment's "Detected by" line, and a
  `detectedBy` SARIF result property). A CVE is preferred over GHSA so the same
  vulnerability converges on one id across scanners (#27).
- Richer dependency finding rendering: aggregated dependency findings now appear
  under a neutral `[dependency]` heading (instead of a single scanner's name)
  with `Package`, `Advisory` (including the shared CVE), `Detected by`, and a
  `Sources` list showing where each scanner observed it. A new `sources` field on
  the finding (per-scanner `tool` + `file`) backs the JSON report (#27).

### Fixed
- PR comment rendering: scanner descriptions are flattened to a single line and
  their Markdown (code fences, headings) neutralized, so an unbalanced ``` fence
  can no longer swallow later findings and the footer into a code block.

## [0.2.0] - 2026-06-15

Supply-chain hardening for the scanner image and signed, verifiable releases
(closes #30).

### Added
- Pinned every bundled binary scanner to an exact version with SHA256 checksum
  verification in the Docker image — gitleaks, zizmor, actionlint, poutine,
  osv-scanner, trivy (#31)
- Hash-locked the pip-installed scanners (semgrep, checkov, zizmor) via a fully
  pinned, multi-arch `requirements-scanners.txt` installed with
  `pip --require-hashes` (#33)
- Renovate configuration to auto-PR scanner version bumps, with a CI job that
  refreshes the pinned checksums (#32)
- Keyless (OIDC) cosign signing of the published container image and of the
  release binary checksums (Sigstore bundle `checksums.txt.sigstore.json`) (#34)
- SBOM (SPDX) attached to every release and as an image attestation (#34)
- Max-mode SLSA build provenance attestation on the container image (#34)
- "Verifying releases" instructions in the README (#34)

### Changed
- Pinned checkov to 3.2.531 (from 3.3.1) so its dependency tree resolves the
  patched aiohttp 3.14.1 and drops the unfixable python-ecdsa Minerva
  dependency that checkov 3.3.x introduced. Revisit when a newer checkov lifts
  its `aiohttp<3.14` cap (#33)

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
