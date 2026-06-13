# syntax=docker/dockerfile:1
# Multi-stage build: install all 8 scanner binaries then copy into a minimal Alpine image.
# Each stage is named after the tool it installs so the final COPY commands are explicit.

# ── Stage: gitleaks ──────────────────────────────────────────────────────────
FROM alpine:3.19 AS gitleaks
RUN apk add --no-cache curl tar && \
    ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    TAG=$(curl -fsSL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" \
          | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_${TAG}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# ── Stage: zizmor ────────────────────────────────────────────────────────────
FROM alpine:3.19 AS zizmor
RUN apk add --no-cache curl && \
    ARCH=$(uname -m | sed 's/x86_64/x86_64-unknown-linux-musl/;s/aarch64/aarch64-unknown-linux-musl/') && \
    TAG=$(curl -fsSL "https://api.github.com/repos/woodruffw/zizmor/releases/latest" \
          | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -fsSL "https://github.com/woodruffw/zizmor/releases/latest/download/zizmor-${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/zizmor

# ── Stage: actionlint ────────────────────────────────────────────────────────
FROM alpine:3.19 AS actionlint
RUN apk add --no-cache curl && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    TAG=$(curl -fsSL "https://api.github.com/repos/rhysd/actionlint/releases/latest" \
          | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/latest/download/actionlint_${TAG}_linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin actionlint && \
    chmod +x /usr/local/bin/actionlint

# ── Stage: poutine ───────────────────────────────────────────────────────────
FROM alpine:3.19 AS poutine
RUN apk add --no-cache curl && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    TAG=$(curl -fsSL "https://api.github.com/repos/boostsecurityio/poutine/releases/latest" \
          | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -fsSL "https://github.com/boostsecurityio/poutine/releases/latest/download/poutine_Linux_${ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin poutine && \
    chmod +x /usr/local/bin/poutine

# ── Stage: osv-scanner ───────────────────────────────────────────────────────
FROM alpine:3.19 AS osv-scanner
RUN apk add --no-cache curl && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    curl -fsSL "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${ARCH}" \
         -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# ── Stage: trivy ─────────────────────────────────────────────────────────────
FROM alpine:3.19 AS trivy
RUN apk add --no-cache curl && \
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ── Stage: python-tools (semgrep + checkov) ──────────────────────────────────
# semgrep and checkov are Python packages; we install them into a venv and
# copy only the venv into the final image to avoid bringing in all of pip.
FROM python:3.12-slim AS python-tools
RUN pip install --no-cache-dir semgrep checkov && \
    # Verify both CLIs are present before the copy stage
    semgrep --version && checkov --version

# ── Stage: builder (compile Muninn) ──────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /muninn .

# ── Final image ──────────────────────────────────────────────────────────────
FROM alpine:3.19

# Runtime dependencies: git is needed by gitleaks; python3 for semgrep/checkov.
RUN apk add --no-cache git python3 py3-pip ca-certificates

# Scanners from Go-built stages
COPY --from=gitleaks    /usr/local/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=zizmor      /usr/local/bin/zizmor      /usr/local/bin/zizmor
COPY --from=actionlint  /usr/local/bin/actionlint  /usr/local/bin/actionlint
COPY --from=poutine     /usr/local/bin/poutine     /usr/local/bin/poutine
COPY --from=osv-scanner /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=trivy       /usr/local/bin/trivy       /usr/local/bin/trivy

# Python tools: copy the installed scripts from the build stage
COPY --from=python-tools /usr/local/bin/semgrep  /usr/local/bin/semgrep
COPY --from=python-tools /usr/local/bin/checkov  /usr/local/bin/checkov
# Copy the Python packages that back the above CLI scripts
COPY --from=python-tools /usr/local/lib/python3.12/site-packages \
                         /usr/local/lib/python3.12/site-packages

# Muninn itself
COPY --from=builder /muninn /usr/local/bin/muninn

LABEL org.opencontainers.image.title="Muninn Security Scanner" \
      org.opencontainers.image.description="All-in-one security scanner for GitHub Actions pipelines" \
      org.opencontainers.image.source="https://github.com/skaldlab/muninn" \
      org.opencontainers.image.licenses="AGPL-3.0"

ENTRYPOINT ["/usr/local/bin/muninn", "scan"]
