---
title: "Configuration"
linkTitle: "Configuration"
weight: 40
type: "docs"
tags: ["setup"]
description: >
  How to configure
---

Here's a list of environment variables used by CAP Operator.

### Controller

- `CERT_MANAGER`: specifies the certificate manager to be used for TLS certificates. Possible values are:
  - `gardener`: ["Gardener" certificate management](https://github.com/gardener/cert-management)
  - `cert-manager.io`: [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- `DNS_MANAGER`: specifies the external DNS manager to be used. Possible values are:
  - `gardener`: ["Gardener" external DNS manager](https://github.com/gardener/external-dns-management)
  - `kubernetes`: [external DNS management from Kubernetes](https://github.com/kubernetes-sigs/external-dns)
- `PROMETHEUS_ADDRESS`: URL of the Prometheus server (or service) for executing PromQL queries e.g. `http://prometheus-operated.monitoring.svc.cluster.local:9090`. If no URL is supplied, the controller will not start the version monitoring function.
- `PROM_ACQUIRE_CLIENT_RETRY_DELAY`: Time delay between retries when a Prometheus client creation and connection check fails.
- `METRICS_EVAL_INTERVAL`: Time interval between subsequent iterations where outdated versions are identified and queued for evaluation.