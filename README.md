# meshscan

**Audit Istio service mesh configuration for common misconfigurations.**

meshscan reads your cluster's Istio resources (VirtualServices, DestinationRules, PeerAuthentications) and Kubernetes Pod specs, then reports semantic issues that `istioctl analyze` doesn't catch: configurations that parse correctly but break traffic in subtle ways.

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

meshscan report: namespace all namespaces
87 issues: 7 critical, 79 high, 1 medium, 0 low

[CRITICAL] production/PeerAuthentication
  check: mtls-enforcement
  ...

[HIGH] staging/VirtualService/payment-service
  check: dead-subsets
  ...
```

## Checks

| Check | Severity | What it finds |
|---|---|---|
| `mtls-enforcement` | CRITICAL | Namespace with no PeerAuthentication (mTLS not enforced) or a mesh-wide PERMISSIVE policy |
| `dead-subsets` | HIGH | VirtualService routes to a subset not defined in the corresponding DestinationRule (produces 503) |
| `outlier-detection` | HIGH | DestinationRule with no outlier detection configured (unhealthy pods stay in rotation) |
| `sidecar-coverage` | HIGH | Running pod without `istio-proxy` sidecar that hasn't explicitly opted out |
| `missing-dr` | MEDIUM | VirtualService host with no DestinationRule (no traffic policy applied) |
| `retry-without-timeout` | MEDIUM | VirtualService with `retries.attempts > 0` but no `timeout` (unbounded retry amplification possible) |

## Install

```bash
go install github.com/n0rm4l-me/meshscan/cmd/meshscan@latest
```

Or build from source:

```bash
git clone https://github.com/n0rm4l-me/meshscan
cd meshscan && make build
```

## Usage

```bash
# Audit a single namespace
meshscan -n my-namespace

# Audit all namespaces at once
meshscan -A

# Use a non-default kubeconfig context
meshscan -n my-namespace --context staging

# Machine-readable output for CI
meshscan -A --json | jq '.[] | select(.severity == "CRITICAL")'

# Filter out infrastructure namespaces when using -A
meshscan -A --json | jq '[.[] | select(.namespace | test("^(kube-|gke-|gmp-|istio-)") | not)]'

# Extend the API timeout (default: 30s)
meshscan -A --timeout 60s

# Print the installed version
meshscan --version

# Exit code: 0 = no findings, 1 = findings present
```

## Permissions

meshscan requires `list` access to the following resources:

| Resource | API group | Namespace |
|---|---|---|
| `virtualservices`, `destinationrules` | `networking.istio.io` | target namespace |
| `peerauthentications` | `security.istio.io` | target namespace + `istio-system` |
| `pods` | (core) | target namespace |
| `namespaces` | (core) | cluster-wide (`-A` only) |

Example ClusterRole for CI use:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: meshscan
rules:
- apiGroups: [networking.istio.io]
  resources: [virtualservices, destinationrules]
  verbs: [list]
- apiGroups: [security.istio.io]
  resources: [peerauthentications]
  verbs: [list]
- apiGroups: [""]
  resources: [pods, namespaces]
  verbs: [list]
```

If meshscan lacks access to `istio-system` PeerAuthentications, it prints a warning to stderr and continues; the mTLS check may miss mesh-wide policies.

## Known limitations

**External host heuristic.** `missing-dr` and `dead-subsets` skip hosts that look external: anything containing a dot that doesn't end in `.svc.cluster.local`. This avoids false positives for real external FQDNs, but it also silently skips cross-namespace short refs like `svc.other-ns` and custom internal domains like `payments.internal`. If you route to services in other namespaces using dot notation, those hosts won't be checked.

**System namespace noise with `-A`.** When scanning all namespaces, GKE and Kubernetes system namespaces (`kube-system`, `gke-*`, `gmp-*`) generate many `sidecar-coverage` findings for infrastructure DaemonSets that intentionally have no Istio sidecar. Filter them out with `--json` and `jq` (see Usage above).

## Why not `istioctl analyze`?

`istioctl analyze` is great for schema validation: it catches missing Services, unknown hosts, and spec errors. meshscan catches a different class of problems: configurations that are syntactically valid but semantically broken or dangerous at runtime. For example, `istioctl analyze` won't flag a DestinationRule that's missing outlier detection. The rule is valid, but it silently sends traffic to unhealthy pods.

The two tools complement each other.

## License

Apache 2.0
