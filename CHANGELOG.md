# Changelog

## [Unreleased]

### Changed

- Scanner dependency updates: osv-scanner `2.5.1`, trivy `0.74.0`,
  semgrep `1.173.0`.
- checkov remains pinned at `3.2.531`: `3.2.532+` and `3.3.x` reintroduce
  transitive `ecdsa` (`>=0.19.0,<1.0.0`), currently affected by
  `PYSEC-2026-1325` / `CVE-2024-23342` with no fixed ecdsa release yet.
- The secure `aiohttp>=3.14.3` floor remains enforced.
- asteval floor raised to >=1.0.10 (hashed override) for GHSA-89v8-rhwq-hf77
  (CVE-2026-55244) and GHSA-9w56-46f6-3qhx; checkov 3.2.531 still requires
  asteval 1.0.6.
- Removed obsolete semgrep dependency overrides (`click`, `mcp`) after semgrep
  upstream constraint updates; lockfile now resolves to `click 8.4.2` and
  `mcp 1.29.0` without override pins.
- Post-release follow-up: update all user-facing latest-version references
  (website pages, README snippets, and docs examples) to the released tag.

## [0.3.8] - 2026-08-10

### Changed

- Docker image scanner update: osv-scanner 2.5.0 (full osv-scalibr pipeline;
  checkov remains at 3.2.531 pending aiohttp cap lift).
- GitPython floor raised to >=3.1.58 for GHSA-hmq2-w58f-27jc and related
  3.1.58 hardening advisories (path traversal / unguarded git option sinks).

## [0.3.7] - 2026-08-04

### Changed

- GitPython floor raised to >=3.1.55 for GHSA-94p4-4cq8-9g67 (incomplete
  expandvars fix in create_remote / Remote.add).
- cryptography floor raised to >=50.0.0 for GHSA-g6cj-pr64-35w5
  (CVE-2026-69247: PKCS#7 EnvelopedData Bleichenbacher oracle).
- aiohttp floor raised to >=3.14.3; scanner lockfile recompiled with click 8.3.3
  and mcp 1.28.1 security overrides.
- Docker image scanner updates: trivy 0.73.0, semgrep 1.172.0, zizmor 1.29.0
  (checkov remains at 3.2.531 pending aiohttp cap lift; 3.2.533+ also caps
  `aiohttp<3.14`).

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
