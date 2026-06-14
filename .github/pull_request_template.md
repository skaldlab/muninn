## Summary

<!-- What changed and why? One scanner or feature per PR. -->

-

## Type of change

- [ ] Bug fix
- [ ] New scanner or reporter
- [ ] Documentation
- [ ] CI / release / tooling
- [ ] Other (describe below)

## Test plan

<!-- How did you verify this? All CI checks must pass, including 90% coverage. -->

- [ ] `make test`
- [ ] `go vet ./...`
- [ ] Integration tests (if scanner binaries are available): `go test -tags integration ./integration/...`
- [ ] Muninn self-scan / workflow changes validated locally or in CI

## Checklist

- [ ] Conventional commit title (e.g. `fix:`, `feat:`, `docs:`, `chore:`)
- [ ] New scanner includes fixture, tests, `main.go` wiring, and README table entry
- [ ] No unrelated changes bundled in this PR
- [ ] [CONTRIBUTING.md](../CONTRIBUTING.md) conventions followed

## Additional notes

<!-- Screenshots, breaking changes, follow-ups, etc. -->

---

Muninn is built by [Skald Lab](https://skaldlab.dev).

**Security vulnerabilities:** do not discuss in this PR. Email [security@skaldlab.dev](mailto:security@skaldlab.dev). See [SECURITY.md](../SECURITY.md).
