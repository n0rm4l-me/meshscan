# Contributing

Thanks for helping to improve meshscan. Bug reports, new checks and documentation fixes are all welcome.

## Setup

You need the Go version in `go.mod` and, for linting, [golangci-lint](https://golangci-lint.run/) v2.

```bash
make build    # ./meshscan with version information
make check    # go vet, golangci-lint and the tests with the race detector
make cover    # coverage per function
```

CI runs the same checks, plus `go mod tidy` and `govulncheck`. Run `make fmt` before you commit; the linter also verifies formatting and import grouping (standard library, third party, then this module).

## Layout

| Path | Role |
|---|---|
| `cmd/meshscan` | Tiny `main`: wires signals, the terminal check and the build version into `internal/cli` |
| `internal/cli` | Flags, validation, exit codes, the scan loop |
| `internal/collector` | Reads resources from the cluster into one `model.Snapshot` per namespace |
| `internal/checks` | The audit rules, the registry, and annotation-based suppression |
| `internal/model` | `Snapshot`, `Finding`, `Severity` |
| `internal/output` | Human, JSON and SARIF writers |
| `internal/version` | Build identity |

A check is a pure function from a `Snapshot` to findings. It never talks to the cluster, which keeps checks trivial to test.

## Adding a check

1. Add the implementation in `internal/checks`, as `func CheckXxx(snap *model.Snapshot) []model.Finding`.
2. Add a name constant and a registry entry in `internal/checks/registry.go`. The name is public interface (`--checks`, annotations, reports): lower-case kebab-case, and never renamed once released. Set `Severity` to the highest severity the check can report.
3. Every finding needs a `Fix` that tells the reader what to change. The resource is `Kind/name`; the suppression annotation looks resources up by that form.
4. Write a table test next to it. Assert the severity, resource and message of each finding, not just how many there are. `TestEveryCheckReportsUnderItsOwnName` already verifies the registry wiring once your check can fire on `dirtySnapshot` in `registry_test.go`; extend that snapshot if it cannot.
5. If the check needs a new kind of resource, add it to `model.Snapshot`, to the collector, to the RBAC tables in the README, and to the collector tests.
6. Add a row to the checks table in the README and an entry to `CHANGELOG.md`.

Prefer silence over a false positive. When a snapshot cannot prove something (a Gateway or DestinationRule in another namespace, an external host), skip it and document the limit in the README's "Known limitations".

## Pull requests

- Keep a change focused, and explain the user-visible effect in the description.
- New behavior comes with tests; bug fixes come with a test that fails without the fix.
- Update `CHANGELOG.md` under `Unreleased` for anything a user would notice.
- Commit messages are short and in the imperative mood, for example `Skip host-network pods in sidecar-coverage`.

## Releasing

`main` is protected: only the maintainer can update it, so contributions arrive as pull requests that the maintainer merges.

To cut a release, the maintainer:

1. Moves the `Unreleased` entries of `CHANGELOG.md` under a new `## [X.Y.Z] - YYYY-MM-DD` heading and updates the link references at the bottom.
2. Waits for CI to pass on `main`, including `govulncheck`.
3. Pushes an annotated tag `vX.Y.Z`.

The release workflow then publishes the archives, the checksums and the container image, and uses that changelog section as the release notes. It fails early when the section is missing. A tag cannot be reused once the Go module proxy has seen it, so check CI before tagging.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
