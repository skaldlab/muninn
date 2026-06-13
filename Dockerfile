# syntax=docker/dockerfile:1
#
# Multi-stage build for Muninn.
#
# All binary scanners land in a single 'tools' stage, which makes the download
# logic easy to audit and cache efficiently.  Python tools get their own stage
# so the heavy site-packages layer is isolated.
#
# Two download helpers are provided:
#   gh_ver  — resolves the latest version via HTTP redirect (no API quota used).
#             Use when the asset filename convention is stable and well-known.
#   gh_asset — resolves the exact download URL via the GitHub releases API JSON.
#              Use when the naming convention is project-specific (e.g. cargo-dist
#              includes the version in the filename; goreleaser arch naming varies).

# ── tools: download all binary scanners ──────────────────────────────────────
FROM alpine:3.19 AS tools

RUN apk add --no-cache curl tar

# gh_ver: resolve latest release version via HTTP redirect, no API call needed.
# Usage: gh_ver OWNER/REPO  →  "1.2.3"
RUN <<'EOF'
cat > /usr/local/bin/gh_ver << 'SCRIPT'
#!/bin/sh
set -e
curl -fsSLI -o /dev/null -w "%{url_effective}" \
  "https://github.com/$1/releases/latest" | sed "s|.*/tag/v||"
SCRIPT
chmod +x /usr/local/bin/gh_ver
EOF

# gh_asset: find the download URL for a release asset by grepping the releases
# JSON for a filename pattern.  Uses one API call per invocation but correctly
# handles any naming convention (goreleaser, cargo-dist, bespoke scripts, etc.).
# Usage: gh_asset OWNER/REPO FILENAME_PATTERN  →  download URL
RUN <<'EOF'
cat > /usr/local/bin/gh_asset << 'SCRIPT'
#!/bin/sh
set -e
curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
  | grep "browser_download_url" \
  | grep "$2" \
  | head -1 \
  | sed 's/.*"browser_download_url": "\([^"]*\)".*/\1/'
SCRIPT
chmod +x /usr/local/bin/gh_asset
EOF

# gitleaks — secrets detection
# Goreleaser asset: gitleaks_VERSION_linux_{x64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    VER=$(gh_ver gitleaks/gitleaks) && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# zizmor — CI/CD pipeline security
# cargo-dist asset: zizmor-VERSION-TARGET.tar.gz  (version is part of the filename)
RUN ARCH=$(uname -m | sed 's/x86_64/x86_64-unknown-linux-musl/;s/aarch64/aarch64-unknown-linux-musl/') && \
    DL=$(gh_asset woodruffw/zizmor "${ARCH}.tar.gz") && \
    curl -fsSL "${DL}" | tar -xz -C /usr/local/bin zizmor && \
    chmod +x /usr/local/bin/zizmor

# actionlint — GitHub Actions linter
# Goreleaser asset: actionlint_VERSION_linux_{amd64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    VER=$(gh_ver rhysd/actionlint) && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${VER}/actionlint_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin actionlint && \
    chmod +x /usr/local/bin/actionlint

# poutine — supply chain pipeline risks
# Use gh_asset to avoid guessing whether the project uses amd64 or x86_64 naming.
RUN ARCH=$(uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/') && \
    DL=$(gh_asset boostsecurityio/poutine "Linux_${ARCH}.tar.gz") && \
    curl -fsSL "${DL}" | tar -xz -C /usr/local/bin poutine && \
    chmod +x /usr/local/bin/poutine

# osv-scanner — dependency CVEs (single static binary, no tarball)
# Goreleaser asset: osv-scanner_linux_{amd64|arm64}
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    VER=$(gh_ver google/osv-scanner) && \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${VER}/osv-scanner_linux_${ARCH}" \
         -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# trivy — container / filesystem scanner (official install script)
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
         | sh -s -- -b /usr/local/bin

# ── python-tools: semgrep + checkov ──────────────────────────────────────────
FROM python:3.12-slim AS python-tools
RUN pip install --no-cache-dir semgrep checkov && \
    semgrep --version && checkov --version

# ── builder: compile Muninn ───────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /muninn .

# ── final image ───────────────────────────────────────────────────────────────
FROM alpine:3.19

# git: needed by gitleaks for commit history scanning
# python3: needed to run semgrep and checkov
# ca-certificates: needed for HTTPS calls by scanners
RUN apk add --no-cache git python3 ca-certificates

COPY --from=tools /usr/local/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=tools /usr/local/bin/zizmor      /usr/local/bin/zizmor
COPY --from=tools /usr/local/bin/actionlint  /usr/local/bin/actionlint
COPY --from=tools /usr/local/bin/poutine     /usr/local/bin/poutine
COPY --from=tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=tools /usr/local/bin/trivy       /usr/local/bin/trivy

COPY --from=python-tools /usr/local/bin/semgrep  /usr/local/bin/semgrep
COPY --from=python-tools /usr/local/bin/checkov  /usr/local/bin/checkov
COPY --from=python-tools /usr/local/lib/python3.12/site-packages \
                         /usr/local/lib/python3.12/site-packages

COPY --from=builder /muninn /usr/local/bin/muninn

LABEL org.opencontainers.image.title="Muninn Security Scanner" \
      org.opencontainers.image.description="All-in-one security scanner for GitHub Actions pipelines" \
      org.opencontainers.image.source="https://github.com/skaldlab/muninn" \
      org.opencontainers.image.licenses="AGPL-3.0"

ENTRYPOINT ["/usr/local/bin/muninn"]
