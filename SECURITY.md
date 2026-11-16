# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting instead: open the **Security** tab of the repository and choose **Report a vulnerability**. Include the meshscan version (`meshscan --version`), what you did, and what you expected to happen.

Reports are handled on a best-effort basis. Once a fix is released, the advisory credits the reporter unless they prefer to stay anonymous.

## Supported versions

Security fixes go into the latest released version. Older versions are not patched.

## What meshscan touches

Knowing the footprint helps when you review a finding or grant access:

- **Read-only.** meshscan only issues `list` requests, plus an optional `get` of the Namespace object. It never creates, patches or deletes anything.
- **No Secrets.** It does not read Secrets or ConfigMaps. It reads Istio networking and security resources, Pods, and Namespaces.
- **Pod specs are read, not logs.** Only metadata and container names are inspected.
- **Output may contain resource names.** Reports include namespace, workload and Gateway names. Treat report files, JSON and SARIF output as internal data.
- **Credentials.** meshscan uses the kubeconfig or in-cluster credentials of the caller and stores nothing.

Grant it the narrowest ClusterRole listed in the README, and use a dedicated ServiceAccount when running it on a schedule.
