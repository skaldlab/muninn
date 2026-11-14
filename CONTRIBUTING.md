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

### Bitbucket coverage

Unit and integration tests simulate Bitbucket Pipelines with `BITBUCKET_*`
env vars and an `httptest` stand-in for the Cloud REST API (`BITBUCKET_API_URL`).
They cover PR comment upsert, Code Insights, scanner defaults, and
`pipeline-check` via a fake `pipeline_check` binary.

There is **no** CI job that calls the real Bitbucket API or runs against a live
workspace — that would need secrets and a dedicated test project. Manual smoke
against your own Bitbucket Cloud repo (using `examples/bitbucket-pipelines.yml`)
is the live check.

## PR conventions
- One scanner or feature per PR
- Squash merge only
- Conventional commit titles
- All CI checks must pass including 95% coverage

## Contact
hello@skaldlab.dev
