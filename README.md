# Muninn

[![CI](https://github.com/skaldlab/muninn/actions/workflows/ci.yml/badge.svg)](https://github.com/skaldlab/muninn/actions/workflows/ci.yml)
[![CodeQL](https://github.com/skaldlab/muninn/actions/workflows/codeql.yml/badge.svg)](https://github.com/skaldlab/muninn/actions/workflows/codeql.yml)
[![Release](https://badgen.net/github/release/skaldlab/muninn)](https://github.com/skaldlab/muninn/releases)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.26.4-blue?logo=go)](https://go.dev/)

**Muninn** is an all-in-one open-source security scanner for GitHub Actions pipelines and self-hosted CI, built by [Skald Lab](https://skaldlab.dev).

Named after Odin's raven of Memory from Norse mythology, Muninn remembers every vulnerability it has ever seen — and reports them all back in one unified format.

Muninn orchestrates eight best-in-class open-source scanners, normalizes their output into a single finding schema, and delivers results as GitHub PR comments, SARIF uploads, and structured JSON — with a single `uses:` line.

---

## Quick Start

Add this to any GitHub Actions workflow:

```yaml
- name: Muninn Security Scan
  uses: skaldlab/muninn@v0.3.0
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: high
```

Muninn runs all eight scanners, posts a summary comment on your pull request, uploads SARIF to the GitHub Security tab, and fails the check when findings meet or exceed your `fail-on` threshold.

---

## What Muninn Scans

| Scanner | What it finds | Upstream |
|---|---|---|
| **gitleaks** | Secrets, API keys, and credentials in source | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| **zizmor** | CI/CD pipeline misconfigurations and injection risks | [woodruffw/zizmor](https://github.com/woodruffw/zizmor) |
| **actionlint** | GitHub Actions syntax errors and security anti-patterns | [rhysd/actionlint](https://github.com/rhysd/actionlint) |
| **poutine** | Supply chain risks in CI/CD (unpinned actions, risky patterns) | [boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) |
| **semgrep** | Application SAST (injection, insecure patterns, secrets in code) | [semgrep.dev](https://semgrep.dev) |
| **osv-scanner** | Known CVEs in dependencies (Go, npm, pip, and more) | [google/osv-scanner](https://github.com/google/osv-scanner) |
| **trivy** | Container image and filesystem vulnerabilities | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **checkov** | Infrastructure-as-Code misconfigurations (Terraform, K8s, Docker) | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |

### Cross-scanner deduplication

Running multiple dependency scanners means the same CVE can surface more than
once — OSV-Scanner flags it in a lockfile while Trivy flags it in a container
layer. Muninn collapses these into a single finding keyed on the advisory id
(a `CVE-…` is preferred over `GHSA-…` so the same vulnerability converges across
scanners) scoped to the affected package, so distinct packages sharing a CVE
stay separate.

Because an aggregated finding no longer belongs to one tool, dependency findings
render under a neutral `[dependency]` heading (rather than `[osv-scanner]`) with
structured detail, and the scanners are surfaced via attribution instead:

- **PR comment** — `Package`, `Advisory` (with the shared CVE in parentheses),
  `Detected by`, and a `Sources` list showing where each scanner saw it
  (e.g. `package-lock.json (osv-scanner)`, `node:18 (trivy)`).
- **JSON report** — `detected_by` (the scanner list) and `sources` (per-scanner
  `tool` + `file` pairs).
- **SARIF** — a `detectedBy` property on the result.

The severity summary counts these aggregated unique findings, not raw scanner
hits, because deduplication runs before any report is written.

---

## Configuration

Create a `muninn.yml` at the root of your repository to customize scanner behavior, severity thresholds, and suppressions.

```yaml
version: 1

# Minimum severity to fail the run.
# Options: critical | high | medium | low | info
fail-on: critical

scanners:
  gitleaks:
    enabled: true

  zizmor:
    enabled: true

  actionlint:
    enabled: true

  poutine:
    enabled: true

  semgrep:
    enabled: true
    rulesets:
      - p/security-audit
      - p/secrets
    exclude-paths:
      - tests/
      - fixtures/

  osv-scanner:
    enabled: true

  trivy:
    enabled: true
    severity: [CRITICAL, HIGH]
    ignore-unfixed: true

  checkov:
    enabled: true
    skip-checks: []

# Suppress specific findings. Every entry must include a reason.
suppressions:
  - id: fixtures/
    reason: "Intentional test fixtures, not real secrets or vulnerabilities"
    expires: ""

  - fingerprint: abc123def456
    reason: "Known false positive in generated code"
    expires: "2026-12-31T23:59:59Z"

  - tool: gitleaks
    rule-id: generic-api-key
    reason: "Test fixture file, not a real secret"
    expires: ""
```

### Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | `int` | `1` | Config schema version. Must be `1`. |
| `fail-on` | `string` | `critical` | Minimum severity that causes a non-zero exit code |

### Scanner fields

Each key under `scanners` matches a scanner name. All scanners support `enabled` (default `true`).

| Scanner | Additional fields | Description |
|---|---|---|
| `semgrep` | `rulesets`, `exclude-paths` | Semgrep rule packs and path prefixes to skip |
| `trivy` | `severity`, `ignore-unfixed` | Severity filter and whether to omit unfixed CVEs |
| `checkov` | `skip-checks` | Checkov check IDs to skip |

### Suppression fields

| Field | Description |
|---|---|
| `id` | Suppress findings whose file path contains this substring |
| `fingerprint` | Suppress a specific finding by its Muninn fingerprint |
| `tool` | Scanner name (used with `rule-id`) |
| `rule-id` | Scanner-native rule identifier (used with `tool`) |
| `reason` | **Required.** Human-readable justification |
| `expires` | Optional RFC 3339 UTC timestamp; omit for permanent suppressions |

### Action inputs

| Input | Default | Description |
|---|---|---|
| `token` | `${{ github.token }}` | GitHub token for PR comments and SARIF upload |
| `fail-on` | `critical` | Minimum severity to exit non-zero |
| `config` | `muninn.yml` | Path to config file relative to repository root |
| `format` | `sarif,comment` | Comma-separated output formats: `sarif`, `json`, `comment` |
| `output` | `muninn.sarif` | SARIF output path override |
| `target` | `.` | Path to scan (repository root) |

### Action outputs

| Output | Description |
|---|---|
| `findings-count` | Total non-suppressed findings across all scanners |
| `critical-count` | Critical-severity finding count |
| `high-count` | High-severity finding count |
| `medium-count` | Medium-severity finding count |
| `low-count` | Low-severity finding count |
| `sarif-path` | Path to the generated SARIF report |
| `json-path` | Path to the generated JSON report |

---

## Why Muninn vs Snyk, GHAS, or Manual Tools?

| | Muninn | Snyk | GitHub Advanced Security | Manual tool chain |
|---|---|---|---|---|
| **License** | AGPL-3.0 (open source) | Proprietary SaaS | Proprietary (Enterprise or public repos) | Mixed |
| **Data leaves your repo** | No — runs on your runner | Yes — code uploaded to Snyk | Yes — processed by GitHub | Depends on tool |
| **CI/CD pipeline security** | Yes (zizmor, actionlint, poutine) | Limited | No | Requires assembly |
| **Supply chain / pipeline risks** | Yes (poutine) | Partial | No | Requires assembly |
| **Self-hostable** | Yes — Docker image or binary | No | No | Yes, with effort |
| **Unified findings** | Yes — one schema, one comment | Partial | Partial | No — N different formats |
| **Setup** | One `uses:` line | Account + integration | Org licensing | Install and wire each tool |

Muninn is not a replacement for every security program — it is a practical default for teams that want broad coverage without stitching together eight separate tools.

---

## CLI and Self-Hosted Usage

### Docker (recommended)

The official image bundles Muninn and all eight scanner binaries:

```bash
docker run --rm \
  -v "$(pwd):/github/workspace" \
  -w /github/workspace \
  ghcr.io/skaldlab/muninn:0.3.0 \
  --target . \
  --output json,sarif \
  --fail-on high
```

### Binary

Download a release binary from [GitHub Releases](https://github.com/skaldlab/muninn/releases) or install with Go:

```bash
go install github.com/skaldlab/muninn@v0.3.0
```

Scanner binaries (`gitleaks`, `semgrep`, `checkov`, and the rest) must be on `PATH`. The Docker image includes everything pre-installed.

### Verifying releases

Every release is signed with [cosign](https://github.com/sigstore/cosign) using keyless (OIDC) signing — there are no long-lived keys to trust. The container image also ships with an SBOM and a max-mode SLSA provenance attestation.

Verify the container image:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/skaldlab/muninn/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/skaldlab/muninn:0.3.0
```

Verify release binaries via the signed checksums file (download `checksums.txt` and the Sigstore bundle `checksums.txt.sigstore.json` from the release):

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/skaldlab/muninn/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# Then confirm the binary matches the verified checksums:
shasum -a 256 -c checksums.txt
```

Inspect the image's SBOM and SLSA provenance attestations (attached by BuildKit):

```bash
docker buildx imagetools inspect ghcr.io/skaldlab/muninn:0.3.0 \
  --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/skaldlab/muninn:0.3.0 \
  --format '{{ json .Provenance }}'
```

### CLI flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--config` | `CONFIG_PATH` | `muninn.yml` | Path to configuration file |
| `--target` | `SCAN_TARGET` | `.` | Repository root to scan |
| `--fail-on` | `FAIL_ON` | from config | Minimum severity to exit non-zero |
| `--output` | `OUTPUT_FORMATS` | `json` | Comma-separated formats: `json`, `sarif`, `comment` |
| `--version` | — | — | Print version and exit |

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for scanner development guidelines, test commands, and pull request conventions.

---

## License

Muninn is licensed under the [GNU Affero General Public License v3.0](LICENSE). You are free to use, modify, and distribute Muninn — including running it as a service — but modifications must remain open source under AGPL-3.0.

For commercial licensing or enterprise support, contact [hello@skaldlab.dev](mailto:hello@skaldlab.dev).

---

Built with 🐦‍⬛ by [Skald Lab](https://skaldlab.dev)
