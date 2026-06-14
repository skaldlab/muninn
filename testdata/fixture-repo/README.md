# Muninn Integration Test Fixtures

This directory contains **intentionally vulnerable** code and
configuration files used to verify Muninn's scanner integrations.

## ⚠️ These files are fake and unsafe by design

| File | Purpose | Scanner tested |
|------|---------|----------------|
| `secrets.env` | Fake credentials | gitleaks |
| `config/fake-key.pem` | Fake private key | gitleaks |
| `.github/workflows/vulnerable.yml` | Dangerous workflow patterns | zizmor, actionlint |
| `src/app.py` | Insecure code patterns | semgrep |
| `terraform/main.tf` | IaC misconfigurations | checkov |

**Do not copy any code from this directory into production.**
All secrets are fake and will not work.
