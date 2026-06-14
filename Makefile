.PHONY: test coverage coverage-html fmt lint build check hooks

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
