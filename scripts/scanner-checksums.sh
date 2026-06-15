#!/usr/bin/env bash
#
# Print the linux amd64/arm64 SHA256 sums for the scanner versions currently
# pinned in the Dockerfile. After bumping an `ARG <TOOL>_VERSION` value, run
# this (`make scanner-checksums`) and paste the printed sums into the matching
# Dockerfile blocks. This keeps version + checksum pinning in sync (issue #30).
set -euo pipefail

DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/Dockerfile"

ver() { grep -E "^ARG ${1}=" "$DOCKERFILE" | head -1 | cut -d= -f2; }

dump() { # label  checksums-url  asset-regex
  echo "== ${1} =="
  curl -fsSL "${2}" | grep -E "${3}"
  echo
}

GITLEAKS_VERSION="$(ver GITLEAKS_VERSION)"
ACTIONLINT_VERSION="$(ver ACTIONLINT_VERSION)"
POUTINE_VERSION="$(ver POUTINE_VERSION)"
OSV_SCANNER_VERSION="$(ver OSV_SCANNER_VERSION)"
TRIVY_VERSION="$(ver TRIVY_VERSION)"

dump "gitleaks ${GITLEAKS_VERSION}" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
  'linux_(x64|arm64)\.tar\.gz$'

dump "actionlint ${ACTIONLINT_VERSION}" \
  "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_checksums.txt" \
  'linux_(amd64|arm64)\.tar\.gz$'

dump "poutine ${POUTINE_VERSION}" \
  "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/poutine_${POUTINE_VERSION}_checksums.txt" \
  'Linux_(x86_64|arm64)\.tar\.gz$'

dump "osv-scanner ${OSV_SCANNER_VERSION}" \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS" \
  'linux_(amd64|arm64)$'

dump "trivy ${TRIVY_VERSION}" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
  'Linux-(64bit|ARM64)\.tar\.gz$'
