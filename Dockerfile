# syntax=docker/dockerfile:1
#
# Multi-stage build for Muninn.
#
# Libc strategy: the final image is Debian-based (glibc) rather than Alpine
# (musl).  This is deliberate — semgrep, checkov, and zizmor are installed via
# pip and ship compiled, glibc-linked components (semgrep-core, zizmor's Rust
# binary) that do not run on musl.  The remaining scanners (gitleaks, actionlint,
# poutine, osv-scanner, trivy) are static Go binaries that run on any libc, so we
# download them in a lightweight Alpine stage and copy them in.
#
# Version detection uses gh_ver, which resolves the latest tag via the GitHub
# releases HTTP redirect (no JSON API call), so we never touch the 60 req/hour
# unauthenticated API rate limit.

# ── tools: download static Go scanner binaries ───────────────────────────────
FROM alpine:3.24 AS tools

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

# gitleaks — secrets detection
# Goreleaser asset: gitleaks_VERSION_linux_{x64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    VER=$(gh_ver gitleaks/gitleaks) && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# actionlint — GitHub Actions linter
# Goreleaser asset: actionlint_VERSION_linux_{amd64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    VER=$(gh_ver rhysd/actionlint) && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${VER}/actionlint_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin actionlint && \
    chmod +x /usr/local/bin/actionlint

# poutine — supply chain pipeline risks
# Goreleaser asset: poutine_Linux_{x86_64|arm64}.tar.gz (raw uname -m for amd64)
RUN ARCH=$(uname -m | sed 's/aarch64/arm64/') && \
    VER=$(gh_ver boostsecurityio/poutine) && \
    curl -fsSL "https://github.com/boostsecurityio/poutine/releases/download/v${VER}/poutine_Linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin poutine && \
    chmod +x /usr/local/bin/poutine

# osv-scanner — dependency CVEs (single static binary, no tarball)
# Goreleaser asset: osv-scanner_linux_{amd64|arm64}
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    VER=$(gh_ver google/osv-scanner) && \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${VER}/osv-scanner_linux_${ARCH}" \
         -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# trivy — container / filesystem scanner (official install script, static binary)
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
         | sh -s -- -b /usr/local/bin

# ── builder: compile Muninn (static, runs on any libc) ───────────────────────
FROM golang:1.26.4-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /muninn .

# ── final image (Debian/glibc) ───────────────────────────────────────────────
FROM python:3.14-slim

# git: gitleaks needs it for commit-history scanning
# ca-certificates: HTTPS calls made by the scanners
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Python/Rust scanners installed natively so their compiled parts match the
# image's glibc.  zizmor ships a Rust binary wheel on PyPI.
RUN pip install --no-cache-dir semgrep checkov zizmor && \
    semgrep --version && checkov --version && zizmor --version

# Static Go scanner binaries
COPY --from=tools /usr/local/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=tools /usr/local/bin/actionlint  /usr/local/bin/actionlint
COPY --from=tools /usr/local/bin/poutine     /usr/local/bin/poutine
COPY --from=tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=tools /usr/local/bin/trivy       /usr/local/bin/trivy

COPY --from=builder /muninn /usr/local/bin/muninn

WORKDIR /github/workspace

# Security: run as non-root (UID 1001 matches GitHub-hosted ubuntu runners).
RUN groupadd -g 1001 muninn && \
    useradd -u 1001 -g muninn -m -d /home/muninn -s /usr/sbin/nologin muninn && \
    chown muninn:muninn /github/workspace

USER muninn

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["/usr/local/bin/muninn", "--version"]

LABEL org.opencontainers.image.title="Muninn Security Scanner" \
      org.opencontainers.image.description="All-in-one security scanner for GitHub Actions pipelines" \
      org.opencontainers.image.source="https://github.com/skaldlab/muninn" \
      org.opencontainers.image.licenses="AGPL-3.0"

ENTRYPOINT ["/usr/local/bin/muninn"]
