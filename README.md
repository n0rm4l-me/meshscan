# meshscan

**Audit Istio service mesh configuration for common misconfigurations.**

meshscan reads your cluster's Istio resources (VirtualServices, DestinationRules, Gateways, EnvoyFilters, PeerAuthentications) and Kubernetes Pod specs, then reports semantic issues that `istioctl analyze` doesn't catch: configurations that parse correctly but break traffic in subtle ways. It is read-only: it only needs `list` access and never changes the cluster.

```
$ meshscan -n production --context my-cluster

meshscan report: namespace production
3 issues: 1 critical, 1 high, 1 medium, 0 low

[CRITICAL] PeerAuthentication
  check: mtls-enforcement
  no PeerAuthentication found; namespace defaults to PERMISSIVE (plaintext allowed)
  fix: kubectl apply -f - <<EOF
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: production
  spec:
    mtls:
      mode: STRICT
  EOF

[HIGH] VirtualService/payment-service
  check: dead-subsets
  routes to payment-service subset=canary but no DestinationRule exists for this host (traffic will 503)
  fix: create a DestinationRule for payment-service with subset canary defined

[MEDIUM] VirtualService/order-service
  check: missing-dr
  routes to order-service but no DestinationRule (no traffic policy applied)
  fix: create a DestinationRule for order-service with outlier detection and connection pool limits
```

When scanning all namespaces with `-A`, each finding is prefixed with its namespace:

```
$ meshscan -A --context my-cluster

meshscan report: all namespaces
87 issues: 7 critical, 79 high, 1 medium, 0 low

[CRITICAL] production/PeerAuthentication
  check: mtls-enforcement
  ...

[HIGH] staging/VirtualService/payment-service
  check: dead-subsets
  ...
```

## Checks

Run `meshscan --list-checks` for the list your binary supports.

| Check | Severity | What it finds |
|---|---|---|
| `mtls-enforcement` | CRITICAL | Namespace whose effective namespace-wide mTLS mode is not STRICT: no PeerAuthentication (and no mesh-wide STRICT policy), or a PERMISSIVE or DISABLE policy. A mode of UNSET inherits from the mesh level, and the oldest namespace-wide policy wins, as in Istio |
| `dead-subsets` | HIGH | VirtualService routes to a subset not defined in the corresponding DestinationRule (produces 503) |
| `outlier-detection` | HIGH | DestinationRule with no outlier detection, neither at the top level nor on every subset (unhealthy pods stay in rotation) |
| `sidecar-coverage` | HIGH | Running pod without `istio-proxy` that hasn't opted out. Host-network pods and pods or namespaces in ambient mode (`istio.io/dataplane-mode`) are skipped |
| `gateway-missing` | HIGH | VirtualService references a Gateway that does not exist in the namespace the reference points to (no ingress traffic routed) |
| `envoyfilter-scope` | HIGH / CRITICAL | EnvoyFilter with neither `workloadSelector` nor `targetRefs` applies to all pods in the namespace; CRITICAL if in `istio-system` (affects the whole mesh) |
| `missing-dr` | MEDIUM | VirtualService destination with no DestinationRule (no traffic policy applied) |
| `retry-without-timeout` | MEDIUM | VirtualService with `retries.attempts > 0` but no `timeout`, or `timeout: 0s` (unbounded retry amplification possible) |

## Install

```bash
go install github.com/n0rm4l-me/meshscan/cmd/meshscan@latest
```

Or build from source:

```bash
git clone https://github.com/n0rm4l-me/meshscan
cd meshscan && make build
```

Tagged releases (`v*`) publish binaries for Linux, macOS and Windows with a checksum file, and a multi-arch container image on `ghcr.io/n0rm4l-me/meshscan`, through [`.github/workflows/release.yml`](.github/workflows/release.yml). The [`Dockerfile`](Dockerfile) builds the same image locally with `make docker`.

## Usage

```bash
# Audit a single namespace
meshscan -n my-namespace

# Audit all namespaces at once, without infrastructure namespaces
meshscan -A --exclude-namespace 'kube-*' --exclude-namespace 'gke-*' --exclude-namespace 'istio-*'

# Use a non-default kubeconfig context
meshscan -n my-namespace --context staging

# Fail a pipeline only on HIGH and above; lower findings are still reported
meshscan -A --fail-on high

# Machine-readable output for CI
meshscan -A -o json | jq '.[] | select(.severity == "CRITICAL")'
meshscan -A -o sarif > meshscan.sarif

# Run only some checks, or all but some
meshscan -n my-namespace --checks mtls-enforcement,dead-subsets
meshscan -n my-namespace --skip-checks sidecar-coverage

# Raise the per-call API timeout (default: 30s) or parallelism (default: 4 namespaces)
meshscan -A --timeout 60s --concurrency 8

# Print the installed version and the available checks
meshscan --version
meshscan --list-checks
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-n`, `--namespace` | | Namespace to audit. Required unless `-A` is used |
| `-A`, `--all-namespaces` | `false` | Audit all namespaces. Mutually exclusive with `-n` |
| `--exclude-namespace` | | Skip namespaces matching a glob such as `kube-*`. Repeatable. With `-A` only |
| `--context`, `--kubeconfig` | current context, standard loading rules | Which cluster to talk to |
| `-o`, `--output` | `human` | `human`, `json` or `sarif`. `--json` is a shorthand for `-o json` |
| `--fail-on` | `low` | Exit with 1 when a finding is at least this severe: `critical`, `high`, `medium`, `low` or `none` |
| `--checks`, `--skip-checks` | all checks | Comma-separated check names. Unknown names are an error |
| `--no-suppress` | `false` | Ignore `meshscan.io/ignore` annotations and report everything |
| `--timeout` | `30s` | Timeout for each Kubernetes API call. `0` means no limit |
| `--concurrency` | `4` | Namespaces collected in parallel, 1 to 32 |
| `--color` | `auto` | `auto`, `always` or `never`. `auto` colors only on a terminal and honors `NO_COLOR` |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | meshscan could not do its job: usage error, cluster error, or an incomplete scan |

An incomplete scan is exit code 2 even when no finding was reported. With `-A`, a namespace that cannot be read (for example, RBAC denies `list pods`) is reported as a warning, the other namespaces are still scanned and printed, and the run ends with 2, because a scan that skipped a namespace cannot claim the mesh is clean. Exclude namespaces you are not meant to read with `--exclude-namespace`.

### Output formats

- `human`: the report shown above, on stdout.
- `json`: an array of findings with `severity`, `check`, `resource`, `namespace`, `message` and `fix`.
- `sarif`: a SARIF 2.1.0 log. Findings describe live cluster resources, not files, so results carry logical locations (`namespace/Kind/name`) and no file locations. Consumers that insist on file locations, GitHub code scanning among them, may reject it.

Warnings and notes always go to stderr, so stdout stays machine-readable.

### Acknowledging findings

An owner who accepts a finding can say so on the resource itself, or on the namespace for findings without a resource such as a missing PeerAuthentication:

```yaml
metadata:
  annotations:
    meshscan.io/ignore: "retry-without-timeout, missing-dr"   # or "*" for every check
```

Suppressed findings are counted in a note on stderr. Auditors can see everything with `--no-suppress`.

## Permissions

meshscan requires `list` access to the following resources:

| Resource | API group | Namespace |
|---|---|---|
| `virtualservices`, `destinationrules`, `gateways`, `envoyfilters` | `networking.istio.io` | target namespace |
| `peerauthentications` | `security.istio.io` | target namespace + `istio-system` |
| `pods` | (core) | target namespace |
| `namespaces` | (core) | cluster-wide: `list` for `-A`, `get` for `-n` (optional) |

Example ClusterRole for CI use:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: meshscan
rules:
- apiGroups: [networking.istio.io]
  resources: [virtualservices, destinationrules, gateways, envoyfilters]
  verbs: [list]
- apiGroups: [security.istio.io]
  resources: [peerauthentications]
  verbs: [list]
- apiGroups: [""]
  resources: [pods]
  verbs: [list]
- apiGroups: [""]
  resources: [namespaces]
  verbs: [get, list]
```

If meshscan lacks access to `istio-system` PeerAuthentications, it prints a warning to stderr and continues; the mTLS check may then report a namespace that a mesh-wide STRICT policy actually protects.

If it cannot `get` the Namespace object with `-n`, it warns and continues without namespace labels and annotations: ambient-mode detection and a namespace-level `meshscan.io/ignore` are then unavailable.

## Running in CI and in the cluster

In a pipeline that already has a kubeconfig:

```yaml
- run: meshscan -A --exclude-namespace 'kube-*' --fail-on high
```

As a scheduled job inside the cluster, with the ClusterRole above bound to a dedicated ServiceAccount (replace the image with the one you build or mirror):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: meshscan
  namespace: meshscan
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: meshscan
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: meshscan
subjects:
- kind: ServiceAccount
  name: meshscan
  namespace: meshscan
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: meshscan
  namespace: meshscan
spec:
  schedule: "0 6 * * *"
  jobTemplate:
    spec:
      backoffLimit: 0
      template:
        spec:
          serviceAccountName: meshscan
          restartPolicy: Never
          containers:
          - name: meshscan
            image: YOUR_REGISTRY/meshscan:TAG
            args: ["-A", "--exclude-namespace", "kube-*", "-o", "json"]
```

Inside a pod meshscan uses the in-cluster credentials automatically.

## Known limitations

**Host resolution.** meshscan reads one namespace at a time. A short destination host such as `payments` is resolved in the namespace of the rule that mentions it, exactly as Istio does, and matches a DestinationRule written as `payments` or `payments.<ns>.svc.cluster.local`. `missing-dr` only judges in-cluster services of the same namespace. For a service of another namespace (`svc.other.svc.cluster.local`) or an external host, `dead-subsets` reports only when a DestinationRule visible in the scanned namespace proves the subset is missing. Hosts under a custom cluster domain (anything other than `.svc.cluster.local`) are treated as external.

**Gateways.** A `gateway-missing` check can only verify Gateways of the VirtualService's own namespace. References such as `istio-system/ingress` are skipped.

**mTLS scope.** `mtls-enforcement` judges the namespace-wide and mesh-wide policies. Workload-scoped PeerAuthentications (with a `selector`) and `portLevelMtls` are not evaluated. The mesh root namespace is assumed to be `istio-system`.

**System namespace noise with `-A`.** GKE and Kubernetes system namespaces (`kube-system`, `gke-*`, `gmp-*`) generate many `sidecar-coverage` findings for infrastructure DaemonSets that intentionally have no Istio sidecar. Exclude them with `--exclude-namespace`.

## Why not `istioctl analyze`?

`istioctl analyze` is great for schema validation: it catches missing Services, unknown hosts, and spec errors. meshscan catches a different class of problems: configurations that are syntactically valid but semantically broken or dangerous at runtime. For example, `istioctl analyze` won't flag a DestinationRule that's missing outlier detection. The rule is valid, but degraded pods (alive, passing health checks, returning 500s) stay in the load balancing pool.

The two tools complement each other.

## Development

```bash
make check    # go vet, golangci-lint and the tests with the race detector
make cover    # coverage per function
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a check, and [SECURITY.md](SECURITY.md) to report a vulnerability. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
