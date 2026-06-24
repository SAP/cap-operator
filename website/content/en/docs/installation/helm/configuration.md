---
title: "Configuration"
linkTitle: "Optional Configuration"
weight: 10
type: "docs"
tags: ["setup"]
description: >
  Optional configuration steps when installing CAP Operator with Helm
---

## Optional Configuration

- ### Enable Service Monitors for metrics

  To enable monitoring via [metrics](../../../usage/operator-metrics) emitted by CAP Operator components, set the following value:
  ```yaml
  monitoring:
    enabled: true # <-- enables creation of service monitors for metrics emitted by CAP Operator components
  ```
  To enable detailed operational metrics for the controller:
  ```yaml
  controller:
      detailedOperationalMetrics: true
  ```
- ### Set up Prometheus integration for _Version Monitoring_

  To use the [Version Monitoring](../../../usage/version-monitoring/) feature, provide a [Prometheus](https://prometheus.io/) server URL to the CAP Operator. When installing with the Helm chart, specify the following values:
  ```yaml
  controller:
    versionMonitoring:
      prometheusAddress: "http://prometheus-operated.monitoring.svc.cluster.local:9090" # <-- example of a Prometheus server running inside the same cluster
      promClientAcquireRetryDelay: "2h"
      metricsEvaluationInterval: "30m" # <-- interval at which version metrics are evaluated
  ```
  On startup, the controller attempts to connect to the Prometheus server and fetch [runtime information](https://prometheus.io/docs/prometheus/latest/querying/api/#runtime-information) to verify the connection. If the connection fails, the controller retries after the delay specified in `controller.versionMonitoring.promClientAcquireRetryDelay`. See default values [here](../helm-values).

  {{% alert title="Note" color="info" %}}
  - When connecting the controller to a Prometheus server running inside the cluster, ensure that the `NetworkPolicy` resources required for connecting to the service in the Prometheus namespace are also created.
  - If the Prometheus service is configured to use TLS, mount the relevant CA root certificates as volumes on the controller.
  {{% /alert %}}

- ### Configure maximum concurrent reconciles

  The controller reconciles each resource type with a built-in default concurrency. To override these defaults, configure the values explicitly:
  ```yaml
  controller:
    maxConcurrentReconciles:
      capApplication: "1"        # default: 1
      capApplicationVersion: "3" # default: 3
      capTenant: "10"            # default: 10
      capTenantOperation: "10"   # default: 10
      domain: "1"                # default: 1
      clusterDomain: "1"         # default: 1
  ```

- ### Configure controller client rate limiting

  To control the rate at which the controller client sends requests to the Kubernetes API server, configure the QPS (queries per second) and burst values:
  ```yaml
  controller:
    clientRateLimiting:
      qps: "20"    # <-- maximum queries per second
      burst: "30"  # <-- maximum burst for throttle
  ```

- ### Configure controller rollout delay

  To introduce a delay before the controller rolls out workloads of relevant application versions on credential update (e.g. to allow a safe rollout window), set the rollout delay:
  ```yaml
  controller:
    rolloutDelay: "1h" # <-- duration to wait before rolling out version workloads on credential update
  ```
