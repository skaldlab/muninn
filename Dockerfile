# syntax=docker/dockerfile:1
#
# Multi-stage build for Muninn.
#
# All binary scanners land in a single 'tools' stage, which makes the download
# logic easy to audit and cache efficiently.  Python tools get their own stage
# so the heavy site-packages layer is isolated.
#
# Version detection uses the GitHub releases redirect URL
# (https://github.com/owner/repo/releases/latest → /releases/tag/vX.Y.Z)
# rather than the JSON API, so we never burn the unauthenticated rate-limit
# of 60 req/hour.

# ── tools: download all binary scanners ──────────────────────────────────────
FROM alpine:3.19 AS tools

RUN apk add --no-cache curl tar

# Resolve the latest release version for a GitHub repo without using the API.
# Writes the bare version string (e.g. "1.2.3") to stdout.
RUN printf '#!/bin/sh\nset -e\ncurl -fsSLI -o /dev/null -w "%%{url_effective}" \\\n  "https://github.com/$1/releases/latest" | sed "s|.*/tag/v||"\n' \
    > /usr/local/bin/gh_ver && chmod +x /usr/local/bin/gh_ver

# gitleaks — secrets detection
# Asset pattern: gitleaks_VERSION_linux_{x64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    VER=$(gh_ver gitleaks/gitleaks) && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# zizmor — CI/CD pipeline security (Rust, musl target)
# Asset pattern: zizmor-{x86_64|aarch64}-unknown-linux-musl.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/x86_64-unknown-linux-musl/;s/aarch64/aarch64-unknown-linux-musl/') && \
    VER=$(gh_ver woodruffw/zizmor) && \
    curl -fsSL "https://github.com/woodruffw/zizmor/releases/download/v${VER}/zizmor-${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin zizmor && \
    chmod +x /usr/local/bin/zizmor

# actionlint — GitHub Actions linter
# Asset pattern: actionlint_VERSION_linux_{amd64|arm64}.tar.gz
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    VER=$(gh_ver rhysd/actionlint) && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${VER}/actionlint_${VER}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin actionlint && \
    chmod +x /usr/local/bin/actionlint

# poutine — supply chain pipeline risks
# Asset pattern: poutine_Linux_{x86_64|arm64}.tar.gz
# Note: uses raw uname -m for amd64 (x86_64), but arm64 (not aarch64) for ARM.
RUN ARCH=$(uname -m | sed 's/aarch64/arm64/') && \
    VER=$(gh_ver boostsecurityio/poutine) && \
    curl -fsSL "https://github.com/boostsecurityio/poutine/releases/download/v${VER}/poutine_Linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin poutine && \
    chmod +x /usr/local/bin/poutine

# osv-scanner — dependency CVEs (single static binary, no tarball)
# Asset pattern: osv-scanner_linux_{amd64|arm64}
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
