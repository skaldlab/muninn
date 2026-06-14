# Contributing to Muninn

Muninn is built by Skald Lab and welcomes contributions.

## Adding a new scanner
1. Implement Scanner interface in internal/scanner/<name>.go
2. Add fixture to testdata/<name>/sample.json
3. Write tests using TestMain subprocess pattern
4. Wire into main.go scan() after existing scanners
5. Add to scanner table in README.md

## Running tests
make test                                     # unit tests
go test -tags integration ./integration/...   # integration tests
make coverage                                 # coverage report

## PR conventions
- One scanner or feature per PR
- Squash merge only
- Conventional commit titles
- All CI checks must pass including 90% coverage

## Contact
hello@skaldlab.dev
