# Muninn

> *Huginn and Muninn fly each day over the spacious earth. I fear for Huginn, that he come not back, yet more anxious am I for Muninn.*
> — Grímnismál, the Prose Edda

**Muninn** (Old Norse: *Memory*) is an open-source security scanner for GitHub Actions pipelines, built by [Skaldlab](https://github.com/skaldlab). Named after Odin's raven of Memory, Muninn remembers every vulnerability it has ever seen — and reports them all back.

Muninn orchestrates **8 best-in-class open-source scanners**, normalises their output into a single finding schema, and delivers results as GitHub PR comments, SARIF uploads, and structured JSON — with a single `uses:` line.

[![CI](https://github.com/skaldlab/muninn/actions/workflows/ci.yml/badge.svg)](https://github.com/skaldlab/muninn/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

---

## Quick start

Add this to any GitHub Actions workflow:

```yaml
- name: Run Muninn
  uses: skaldlab/muninn@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: high
```

That's it. Muninn will run all 8 scanners, post a summary comment on your PR, upload SARIF to the GitHub Security tab, and fail the check if any `high` or `critical` finding is detected.

---

## What Muninn scans

| Scanner | What it finds | Source |
|---|---|---|
| **gitleaks** | Secrets, API keys, credentials committed to source | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| **zizmor** | CI/CD pipeline misconfigurations and injection risks | [github.com/woodruffw/zizmor](https://github.com/woodruffw/zizmor) |
| **actionlint** | GitHub Actions syntax errors and security anti-patterns | [github.com/rhysd/actionlint](https://github.com/rhysd/actionlint) |
| **poutine** | Supply chain risks in CI/CD pipelines (unpinned actions, etc.) | [github.com/boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) |
| **semgrep** | Application code SAST (injection, insecure patterns) | [semgrep.dev](https://semgrep.dev) |
| **osv-scanner** | Known CVEs in your dependencies (Go, npm, pip, etc.) | [github.com/google/osv-scanner](https://github.com/google/osv-scanner) |
| **trivy** | Container image vulnerabilities and misconfigurations | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **checkov** | Infrastructure-as-Code misconfigurations (Terraform, K8s, etc.) | [github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |

---

## Configuration reference

Create a `muninn.yml` at the root of your repository to customise behaviour:

```yaml
version: 1

# Minimum severity to fail the workflow. Options: critical | high | medium | low
fail-on: critical

scanners:
  gitleaks:
    enabled: true

  semgrep:
    enabled: true
    rulesets:
      - p/security-audit
      - p/secrets
    exclude-paths:
      - tests/
      - fixtures/

  zizmor:
    enabled: true

  actionlint:
    enabled: true

  poutine:
    enabled: true

  trivy:
    enabled: true
    severity: [CRITICAL, HIGH]
    ignore-unfixed: true

  osv-scanner:
    enabled: true

  checkov:
    enabled: true
    skip-checks: []

# Suppress specific findings across all runs.
# Every suppression must include a reason.
suppressions:
  - tool: gitleaks
    rule-id: generic-api-key
    reason: "test fixture file, not a real secret"
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `token` | `${{ github.token }}` | GitHub token for PR comments and SARIF upload |
| `fail-on` | `critical` | Minimum severity to exit non-zero |
| `config` | `muninn.yml` | Path to config file |
| `output` | `json,sarif,comment` | Comma-separated list of output formats |
| `target` | `.` | Path to scan (repository root) |

### Action outputs

| Output | Description |
|---|---|
| `findings-count` | Total findings across all scanners |
| `critical-count` | Critical-severity finding count |
| `high-count` | High-severity finding count |
| `sarif-file` | Path to the SARIF file (default: `muninn.sarif`) |
| `json-file` | Path to the JSON report (default: `muninn.json`) |

---

## Why Muninn instead of Snyk or GitHub Advanced Security?

| | Muninn | Snyk | GitHub Advanced Security |
|---|---|---|---|
| **License** | AGPL-3.0 (open source) | Proprietary SaaS | Proprietary (requires GitHub Enterprise or public repos) |
| **Data leaves your repo** | Never — runs entirely in your runner | Yes — code uploaded to Snyk servers | Yes — processed by GitHub |
| **CI/CD-specific checks** | Yes (zizmor, actionlint, poutine) | Limited | No |
| **Supply chain pipeline** | Yes (poutine) | Partial | No |
| **Self-hostable** | Yes — Docker image, runs anywhere | No | No |
| **Composable** | Yes — swap in/out any scanner | No | No |

---

## Development

### Project structure

```
muninn/
├── main.go                      # CLI entrypoint + orchestrator
├── action.yml                   # GitHub Action definition
├── Dockerfile                   # All 8 scanners + Muninn binary
├── internal/
│   ├── normalizer/finding.go    # Unified Finding schema
│   ├── scanner/                 # Scanner interface + 8 implementations
│   ├── reporter/                # SARIF, PR comment, JSON reporters
│   └── config/                  # muninn.yml loader
└── testdata/                    # Fixture outputs for scanner tests
```

### Adding a scanner

1. Create `internal/scanner/<name>.go` implementing the `Scanner` interface.
2. Add `testdata/<name>/sample.json` with a representative output fixture.
3. Write tests in `internal/scanner/<name>_test.go` using the fixture.
4. Wire the scanner into `scan()` in `main.go`.
5. Document it in the scanner table above.

See `.cursorrules` for coding conventions.

### Building locally

```bash
go build ./...
go test ./...
```

---

## License

Muninn is licensed under the [GNU Affero General Public License v3.0](LICENSE).

This means you are free to use, modify, and distribute Muninn — including running it as a service — but any modifications must also be open-sourced under AGPL-3.0. See the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ by [Skaldlab](https://github.com/skaldlab)*
