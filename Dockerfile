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
# Supply chain (see issue #30): every scanner is pinned to an exact version and
# each downloaded binary is verified against a hardcoded SHA256 before use, so a
# compromised upstream release cannot silently flow into the image.  Bumping a
# version REQUIRES refreshing the matching checksum in the same block — run
# `make scanner-checksums` to regenerate them.

# ── tools: download static Go scanner binaries ───────────────────────────────
FROM alpine:3.24 AS tools

RUN apk add --no-cache curl tar

# Pinned scanner versions. Renovate bumps these via the annotations below; the
# SHA256 sums are kept in sync by scripts/update_scanner_checksums.py.
# renovate: datasource=github-releases depName=gitleaks/gitleaks
ARG GITLEAKS_VERSION=8.30.1
# renovate: datasource=github-releases depName=rhysd/actionlint
ARG ACTIONLINT_VERSION=1.7.12
# renovate: datasource=github-releases depName=boostsecurityio/poutine
ARG POUTINE_VERSION=1.1.6
# renovate: datasource=github-releases depName=google/osv-scanner
ARG OSV_SCANNER_VERSION=2.3.8
# renovate: datasource=github-releases depName=aquasecurity/trivy
ARG TRIVY_VERSION=0.71.1

# Target architecture, provided by BuildKit (amd64 | arm64). Declaring the ARG
# makes the predefined value available; we fall back to uname for plain builds.
ARG TARGETARCH

# gitleaks — secrets detection
# Goreleaser asset: gitleaks_VERSION_linux_{x64|arm64}.tar.gz
RUN <<'EOF'
set -eu
arch="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
case "$arch" in
  amd64) asset="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz";   sha="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;;
  arm64) asset="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; sha="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${asset}"
echo "${sha}  /tmp/gitleaks.tgz" | sha256sum -c -
tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks
chmod +x /usr/local/bin/gitleaks
rm /tmp/gitleaks.tgz
EOF

# actionlint — GitHub Actions linter
# Goreleaser asset: actionlint_VERSION_linux_{amd64|arm64}.tar.gz
RUN <<'EOF'
set -eu
arch="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
case "$arch" in
  amd64) asset="actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"; sha="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8" ;;
  arm64) asset="actionlint_${ACTIONLINT_VERSION}_linux_arm64.tar.gz"; sha="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /tmp/actionlint.tgz "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${asset}"
echo "${sha}  /tmp/actionlint.tgz" | sha256sum -c -
tar -xzf /tmp/actionlint.tgz -C /usr/local/bin actionlint
chmod +x /usr/local/bin/actionlint
rm /tmp/actionlint.tgz
EOF

# poutine — supply chain pipeline risks
# Goreleaser asset: poutine_Linux_{x86_64|arm64}.tar.gz (no version in name)
RUN <<'EOF'
set -eu
arch="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
case "$arch" in
  amd64) asset="poutine_Linux_x86_64.tar.gz"; sha="abde716599a65608b023a69ed9316e5f083a7bca48612151c2720835883757ea" ;;
  arm64) asset="poutine_Linux_arm64.tar.gz";  sha="460c90300c6329106b551c150682d12e457365f6436a6cbbd08fe79eb9a98131" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /tmp/poutine.tgz "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/${asset}"
echo "${sha}  /tmp/poutine.tgz" | sha256sum -c -
tar -xzf /tmp/poutine.tgz -C /usr/local/bin poutine
chmod +x /usr/local/bin/poutine
rm /tmp/poutine.tgz
EOF

# osv-scanner — dependency CVEs (single static binary, no tarball)
# Goreleaser asset: osv-scanner_linux_{amd64|arm64}
RUN <<'EOF'
set -eu
arch="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
case "$arch" in
  amd64) asset="osv-scanner_linux_amd64"; sha="bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc" ;;
  arm64) asset="osv-scanner_linux_arm64"; sha="8158b18edd2d03b1a30d905ca91b032bc62262167be8f206c27114f08823e27c" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/${asset}"
echo "${sha}  /usr/local/bin/osv-scanner" | sha256sum -c -
chmod +x /usr/local/bin/osv-scanner
EOF

# trivy — container / filesystem scanner
# Goreleaser asset: trivy_VERSION_Linux-{64bit|ARM64}.tar.gz
RUN <<'EOF'
set -eu
arch="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
case "$arch" in
  amd64) asset="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; sha="3cbae37cd440cd8676e5ce9207fe460b5641c7579a17e9d00f8894928c41a88d" ;;
  arm64) asset="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; sha="a7daaee66817d67a4963e8f9ddf15f5238ee021b55d3cd8695b1b7801afd34a7" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${asset}"
echo "${sha}  /tmp/trivy.tgz" | sha256sum -c -
tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy
chmod +x /usr/local/bin/trivy
rm /tmp/trivy.tgz
EOF

# ── builder: compile Muninn (static, runs on any libc) ───────────────────────
FROM golang:1.26.4-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/skaldlab/muninn/internal/version.Version=${VERSION}" \
    -o /muninn .

# ── final image (Debian/glibc) ───────────────────────────────────────────────
FROM python:3.14-slim

# git: gitleaks needs it for commit-history scanning
# ca-certificates: HTTPS calls made by the scanners
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Python/Rust scanners installed natively so their compiled parts match the
# image's glibc.  zizmor ships a Rust binary wheel on PyPI.  Top-level versions
# are pinned here; full transitive hash pinning (pip --require-hashes) is a
# planned follow-up since it needs a per-arch, hash-locked requirements file.
# renovate: datasource=pypi depName=semgrep
ARG SEMGREP_VERSION=1.166.0
# renovate: datasource=pypi depName=checkov
ARG CHECKOV_VERSION=3.3.1
# renovate: datasource=pypi depName=zizmor
ARG ZIZMOR_VERSION=1.25.2
RUN pip install --no-cache-dir \
      "semgrep==${SEMGREP_VERSION}" \
      "checkov==${CHECKOV_VERSION}" \
      "zizmor==${ZIZMOR_VERSION}" && \
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
