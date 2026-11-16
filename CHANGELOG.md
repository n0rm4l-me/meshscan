# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/). While the major version is 0, a minor release may contain breaking changes.

## [Unreleased]

## [0.3.0] - 2026-11-16

### Added

- Exit code 2 for errors: usage mistakes, cluster errors and incomplete scans are now distinguishable from findings (exit code 1).
- `--fail-on` to choose the severity that fails a run, including `none` for report-only runs.
- `-o, --output` with `human`, `json` and `sarif` (SARIF 2.1.0 with logical locations). `--json` stays as a shorthand.
- `--checks`, `--skip-checks` and `--list-checks`.
- `--exclude-namespace` globs for `-A`, replacing the `jq` recipe in the README.
- `meshscan.io/ignore` annotation on a resource or namespace to acknowledge findings, and `--no-suppress` to show everything.
- `--concurrency` to collect namespaces in parallel, and client-side rate limits raised from client-go's defaults so `-A` scans of large clusters finish in reasonable time.
- `--color auto|always|never`. Color is now off when stdout is not a terminal.
- Version information injected at build time, or recovered from the Go build info for `go install`.
- `mtls-enforcement` now reports DISABLE policies, policies whose mode is UNSET and inherits PERMISSIVE, and namespaces that only have workload-scoped policies. It follows Istio's rule that the oldest namespace-wide policy wins.
- `sidecar-coverage` skips host-network pods and ambient-mode pods or namespaces, and honors the `sidecar.istio.io/inject=false` label as well as the annotation.
- `envoyfilter-scope` accepts `targetRefs` as a valid scope.
- `outlier-detection` accepts outlier detection configured on every subset.
- `retry-without-timeout` treats `timeout: 0s` as no timeout.
- `gateway-missing` verifies `namespace/name`, `./name` and `name.namespace.svc.cluster.local` references that point at the VirtualService's own namespace.
- Apache 2.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, Dependabot, release automation (GoReleaser and a container image), a `Dockerfile`, `govulncheck` and a coverage floor in CI.
- Tests for the collector (fake clientsets), the command line, SARIF output and annotation suppression. Existing check tests now assert severity, resource and message.

### Changed

- `--json` runs now exit with 1 when there are findings. Before, JSON mode always exited 0, which contradicted the documented exit codes.
- Errors, including flag mistakes, exit with 2 instead of 1.
- `--timeout` now applies to each Kubernetes API call, as its help always said. Before, one deadline covered the whole run.
- `-n` together with `-A` is now an error instead of silently preferring `-A`.
- With `-A`, a namespace that cannot be read no longer aborts the scan: the others are reported, a warning names the skipped namespace, and the exit code is 2.
- The `-A` report header reads `all namespaces` instead of `namespace all namespaces`.
- `missing-dr` reports every VirtualService that lacks a DestinationRule, not only the first one per host.
- `missing-dr` and `dead-subsets` normalize hosts: a short name matches an FQDN of the same namespace, host matching is case-insensitive, subsets of several DestinationRules for one host are merged, and wildcard DestinationRules are honored.
- `dead-subsets` no longer reports routes to services of other namespaces or external hosts unless a visible DestinationRule proves the subset is missing. Before, they were reported as having no DestinationRule even when it lived in the other namespace.
- The Makefile no longer overrides `GOMODCACHE` and `GOCACHE`, and builds with `-trimpath` and version information.

### Fixed

- `cmd/meshscan/` was never committed: the unanchored `meshscan` pattern in `.gitignore` also matched the directory. `go install` and `make build` from a fresh clone failed, and CI passed only because no `main` package existed. The patterns are now anchored to the repository root. The tags `v0.1.0` and `v0.2.0` contain no `cmd/` directory and cannot be installed with `go install`; use the first release made after this fix.
- `go.mod` listed `google.golang.org/protobuf` as indirect although the tests import it directly, so `go mod tidy` was not a no-op.
- Several files were not gofmt-clean, and the linter did not check formatting.
- The README claimed `dead-subsets` skips external hosts; the behavior now matches the documentation.

### Security

- Updated `golang.org/x/net` to v0.60.0 and, through it, `golang.org/x/text` to v0.42.0, `golang.org/x/sys` and `golang.org/x/term`. `govulncheck` reported eight vulnerabilities (GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610, GO-2026-6603, GO-2026-5970, GO-2026-5026 and GO-2026-4918) reachable through the HTTP/2 client code used by client-go.

[Unreleased]: https://github.com/n0rm4l-me/meshscan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/n0rm4l-me/meshscan/compare/v0.2.0...v0.3.0
