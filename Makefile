.PHONY: test coverage coverage-html lint build check

test:
	go test -race ./...

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

coverage-html:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	open coverage.html

lint:
	go vet ./...

build:
	go build ./...

check: lint test coverage
