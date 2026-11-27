#!/usr/bin/env bash
# Unit tests emit a coverprofile; integration runs an instrumented muninn binary (GOCOVERDIR).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

THRESHOLD="${MUNINN_COVERAGE_THRESHOLD:-96}"
UNIT_PROFILE="$ROOT/coverdata/unit.out"
INT_DIR="$ROOT/coverdata/integration"
INT_PROFILE="$ROOT/coverdata/integration.out"
rm -rf coverdata
mkdir -p "$ROOT/coverdata"

echo "==> unit tests"
go test -race -count=1 \
  -cover -coverpkg=./... \
  -coverprofile="$UNIT_PROFILE" \
  -covermode=atomic \
  ./...

echo "==> integration tests (instrumented muninn binary)"
export MUNINN_INTEGRATION_GOCOVERDIR="$INT_DIR"
mkdir -p "$INT_DIR"
go test -race -count=1 -cover -coverpkg=./... -tags integration ./integration/...

coverage_out="$ROOT/coverage.out"
if [ -n "$(find "$INT_DIR" -name 'covmeta.*' -print -quit 2>/dev/null || true)" ]; then
  echo "==> merge unit + integration coverage"
  go tool covdata textfmt -i="$INT_DIR" -o="$INT_PROFILE"
  go run github.com/wadey/gocovmerge@latest \
    "$UNIT_PROFILE" "$INT_PROFILE" > "$coverage_out"
else
  echo "==> integration produced no coverage data; using unit profile only"
  cp "$UNIT_PROFILE" "$coverage_out"
fi

COVERAGE="$(go tool cover -func="$coverage_out" | awk '/^total:/ { gsub(/%/, "", $3); print $3 }')"
echo "Total coverage: ${COVERAGE}%"
go tool cover -func="$coverage_out" | tail -1

awk -v cov="$COVERAGE" -v min="$THRESHOLD" 'BEGIN {
  if (cov + 0 >= min + 0) exit 0
  printf "Coverage %s%% is below %s%% threshold\n", cov, min > "/dev/stderr"
  exit 1
}'