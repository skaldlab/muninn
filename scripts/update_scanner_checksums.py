#!/usr/bin/env python3
"""Verify or refresh the pinned scanner SHA256 sums in the Dockerfile.

For every ``asset="<name>"; sha="<sum>"`` pair in the Dockerfile, the expected
SHA256 is resolved from the upstream release checksum manifest (pinned by the
matching ``ARG <TOOL>_VERSION``) and either checked (``--check``, the default)
or rewritten in place (``--write``). This keeps the version and checksum pins
in sync after a Renovate bump (issue #30).

Standard library only, so it runs on a bare GitHub Actions runner with no pip
install. Network access to github.com is required.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"

# ARG name -> (owner/repo, checksum-manifest filename template).
MANIFESTS = {
    "GITLEAKS_VERSION": ("gitleaks/gitleaks", "gitleaks_{v}_checksums.txt"),
    "ACTIONLINT_VERSION": ("rhysd/actionlint", "actionlint_{v}_checksums.txt"),
    "POUTINE_VERSION": ("boostsecurityio/poutine", "poutine_{v}_checksums.txt"),
    "OSV_SCANNER_VERSION": ("google/osv-scanner", "osv-scanner_SHA256SUMS"),
    "TRIVY_VERSION": ("aquasecurity/trivy", "trivy_{v}_checksums.txt"),
}

ARG_RE = re.compile(r"^ARG (\w+)=(\S+)", re.MULTILINE)
PAIR_RE = re.compile(r'asset="(?P<asset>[^"]+)";\s*sha="(?P<sha>[0-9a-f]{64})"')
VAR_RE = re.compile(r"\$\{(\w+)\}")


def read_args(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in ARG_RE.finditer(text)}


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (trusted host)
        return resp.read().decode()


def build_sum_map(args: dict[str, str]) -> dict[str, str]:
    """Map every release asset filename to its published SHA256."""
    sums: dict[str, str] = {}
    for arg, (repo, template) in MANIFESTS.items():
        version = args[arg]
        manifest = template.format(v=version)
        url = f"https://github.com/{repo}/releases/download/v{version}/{manifest}"
        for line in fetch(url).splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                # Manifests list "<sha>  <name>"; binary mode prefixes name with "*".
                sums[parts[-1].lstrip("*")] = parts[0]
    return sums


def expand(asset: str, args: dict[str, str]) -> str:
    return VAR_RE.sub(lambda m: args.get(m.group(1), m.group(0)), asset)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite mismatched sums in place (default: check only)",
    )
    opts = parser.parse_args()

    text = DOCKERFILE.read_text()
    args = read_args(text)
    sums = build_sum_map(args)

    changes: list[str] = []

    def replace(match: re.Match[str]) -> str:
        asset = expand(match.group("asset"), args)
        current = match.group("sha")
        expected = sums.get(asset)
        if expected is None:
            changes.append(f"{asset}: no entry in upstream checksum manifest")
            return match.group(0)
        if expected != current:
            changes.append(f"{asset}: {current} -> {expected}")
            return match.group(0).replace(current, expected)
        return match.group(0)

    updated = PAIR_RE.sub(replace, text)

    if opts.write:
        if updated != text:
            DOCKERFILE.write_text(updated)
            print("Refreshed scanner checksums:")
            for change in changes:
                print(f"  {change}")
        else:
            print("Scanner checksums already match the pinned versions.")
        return 0

    if changes:
        print(
            "Scanner checksums are stale (run `make scanner-checksums-write`):",
            file=sys.stderr,
        )
        for change in changes:
            print(f"  {change}", file=sys.stderr)
        return 1

    print("All scanner checksums match the pinned versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
