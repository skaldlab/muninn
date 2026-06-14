#!/usr/bin/env bash
# Installs scanner binaries required by integration tests.
set -euo pipefail

gh_ver() {
	curl -fsSLI -o /dev/null -w "%{url_effective}" \
		"https://github.com/$1/releases/latest" | sed 's|.*/tag/v||'
}

ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')
VER=$(gh_ver gitleaks/gitleaks)
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_${ARCH}.tar.gz" \
	| tar -xz -C /usr/local/bin gitleaks
chmod +x /usr/local/bin/gitleaks

ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
VER=$(gh_ver rhysd/actionlint)
curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${VER}/actionlint_${VER}_linux_${ARCH}.tar.gz" \
	| tar -xz -C /usr/local/bin actionlint
chmod +x /usr/local/bin/actionlint

pip install --user semgrep zizmor checkov
echo "$HOME/.local/bin" >> "$GITHUB_PATH"

ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
VER=$(gh_ver boostsecurityio/poutine)
ARCH_RAW=$(uname -m | sed 's/aarch64/arm64/')
curl -fsSL "https://github.com/boostsecurityio/poutine/releases/download/v${VER}/poutine_Linux_${ARCH_RAW}.tar.gz" \
	| tar -xz -C /usr/local/bin poutine
chmod +x /usr/local/bin/poutine

VER=$(gh_ver google/osv-scanner)
curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${VER}/osv-scanner_linux_${ARCH}" \
	-o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner

curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
	| sh -s -- -b /usr/local/bin
