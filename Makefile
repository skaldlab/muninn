.PHONY: test coverage coverage-html fmt lint build check hooks scanner-checksums scanner-checksums-check scanner-checksums-write scanners-lock

test:
	go test -race ./...

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

coverage-html:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	open coverage.html

fmt:
	gofmt -w .

lint:
	gofmt -l . | grep . && echo "gofmt: files need formatting (run 'make fmt')" && exit 1 || true
	go vet ./...

build:
	go build ./...

check: lint test coverage

# Install Git hooks from .githooks/ (run once per clone).
hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit .githooks/pre-push
	@echo "Git hooks installed from .githooks/ (pre-commit + pre-push)"

# Print linux amd64/arm64 SHA256 sums for the scanner versions pinned in the
# Dockerfile. Run after bumping an ARG <TOOL>_VERSION, then paste them back.
scanner-checksums:
	@bash scripts/scanner-checksums.sh

# Verify the Dockerfile's hardcoded SHA256 sums match the pinned versions.
scanner-checksums-check:
	@python3 scripts/update_scanner_checksums.py

# Rewrite the Dockerfile's SHA256 sums to match the pinned versions in place.
scanner-checksums-write:
	@python3 scripts/update_scanner_checksums.py --write

# Recompile the hash-locked, multi-arch pip scanner lockfile from the .in file.
# Requires uv (https://docs.astral.sh/uv/). Run after editing requirements-scanners.in.
scanners-lock:
	uv pip compile --universal --generate-hashes --python-version 3.14 \
		requirements-scanners.in -o requirements-scanners.txt
