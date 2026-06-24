---
title: "Configuration"
linkTitle: "Configuration"
weight: 40
type: "docs"
tags: ["setup"]
description: >
  How to configure CAP Operator
---

The following environment variables are used to configure CAP Operator.

### Controller

- `CERT_MANAGER`: The certificate manager used for TLS certificates. Possible values:
  - `gardener`: ["Gardener" certificate management](https://github.com/gardener/cert-management)
  - `cert-manager.io`: [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- `DNS_MANAGER`: The external DNS manager to use. Possible values:
  - `gardener`: ["Gardener" external DNS manager](https://github.com/gardener/external-dns-management)
  - `kubernetes`: [External DNS management from Kubernetes](https://github.com/kubernetes-sigs/external-dns)
- `PROMETHEUS_ADDRESS`: URL of the Prometheus server for executing PromQL queries, for example `http://prometheus-operated.monitoring.svc.cluster.local:9090`. If not set, the controller still runs the version cleanup loop; however, only versions whose workloads have no `deletionRules` defined are eligible for cleanup — versions that have `deletionRules` are skipped until a Prometheus connection becomes available.
- `PROM_ACQUIRE_CLIENT_RETRY_DELAY`: Time delay between retries when Prometheus client creation or connection check fails.
- `METRICS_EVAL_INTERVAL`: Time interval between iterations where outdated versions are identified and queued for evaluation.
- `MAX_CONCURRENT_RECONCILES_CAP_APPLICATION`: Maximum number of concurrent reconciles for `CAPApplication` (for example, `1`).
- `MAX_CONCURRENT_RECONCILES_CAP_APPLICATION_VERSION`: Maximum number of concurrent reconciles for `CAPApplicationVersion` (for example, `3`).
- `MAX_CONCURRENT_RECONCILES_CAP_TENANT`: Maximum number of concurrent reconciles for `CAPTenant` (for example, `10`).
- `MAX_CONCURRENT_RECONCILES_CAP_TENANT_OPERATION`: Maximum number of concurrent reconciles for `CAPTenantOperation` (for example, `10`).
- `MAX_CONCURRENT_RECONCILES_DOMAIN`: Maximum number of concurrent reconciles for `Domain` (for example, `1`).
- `MAX_CONCURRENT_RECONCILES_CLUSTER_DOMAIN`: Maximum number of concurrent reconciles for `ClusterDomain` (for example, `1`).
- `CLIENT_QPS`: Maximum queries per second for the Kubernetes client-side rate limiter (for example, `25`). Defaults to `25`.
- `CLIENT_BURST`: Maximum burst size for the Kubernetes client-side rate limiter (for example, `50`). Defaults to `50`.
- `ROLLOUT_DELAY`: Delay window used to batch credential-rotation work triggered by BTP service secret changes. Accepts Go duration strings (for example, `30m`, `2h`). Defaults to `1h`. Values below `30s` are clamped to `30s`.
