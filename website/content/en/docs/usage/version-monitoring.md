---
title: "Version Monitoring"
linkTitle: "Version Monitoring"
weight: 60
type: "docs"
description: >
  How to monitor versions for automatic cleanup
---

In a continuous delivery environment where new application versions are deployed frequently, monitoring and cleaning up older unused versions is important for conserving cluster resources (compute, memory, storage) and keeping the system tidy. CAP Operator allows application developers and operations teams to define how an application version can be monitored for usage.

## Integration with Prometheus

[Prometheus](https://prometheus.io/) is the industry standard for monitoring application metrics and provides a wide variety of tools for managing and reporting metrics. The CAP Operator controller can be connected to a Prometheus server by setting the `PROMETHEUS_ADDRESS` environment variable (see [Configuration](../../configuration)). The controller then queries application-related metrics based on the workload specification of `CAPApplicationVersions`. If no Prometheus address is supplied, the version monitoring function is not started.

## Configure `CAPApplication`

Version cleanup monitoring must be explicitly enabled for a CAP application using the annotation `sme.sap.com/enable-cleanup-monitoring`. The annotation accepts the following values:

|Value|Behavior|
|--|--|
|`dry-run`|When a `CAPApplicationVersion` is evaluated as eligible for cleanup, a `ReadyForDeletion` event is emitted without deleting the version.|
|`true`|When a `CAPApplicationVersion` is evaluated as eligible for cleanup, the version is deleted and a `ReadyForDeletion` event is emitted.|

## Configure `CAPApplicationVersion`

For each _deployment workload_ in a `CAPApplicationVersion`, you can define:
1. Deletion rules: Criteria based on metrics that, when satisfied, mark the workload as eligible for removal.
2. Scrape configuration: Defines how metrics are scraped from the workload service.

#### Deletion Rules (Variant 1) based on Metric Type

The following example shows a workload named `backend` configured with deletion rules based on multiple metrics.
```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  namespace: demo
  name: cav-demo-app-1
spec:
  workloads:
    - name: backend
      deploymentDefinition:
        monitoring:
          deletionRules:
            metrics:
              - calculationPeriod: 90m
                name: current_sessions
                thresholdValue: "0"
                type: Gauge
              - calculationPeriod: 2h
                name: total_http_requests
                thresholdValue: "0.00005"
                type: Counter
```
This tells CAP Operator that workload `backend` provides two metrics that can be monitored for usage.

- Metric `current_sessions` is of type `Gauge`, representing an absolute value at any point in time. CAP Operator queries Prometheus with a PromQL expression that calculates the average value over the specified calculation period. The average values from each time series are summed to get the evaluated value, which is then compared against the threshold to determine eligibility for cleanup.

  |Evaluation steps for metric type `Gauge`|
  |-|
  |Execute PromQL expression `sum(avg_over_time(current_sessions{job="cav-demo-app-1-backend-svc",namespace="demo"}[90m]))` to get the evaluated value|
  |Check whether evaluated value <= 0 (the specified `thresholdValue`)|

- Metric `total_http_requests` is of type `Counter`, representing a cumulative value that can only increase. CAP Operator queries Prometheus with a PromQL expression that calculates the rate of increase over the specified period. The rates from each time series are summed to get the evaluated value, which is compared against the threshold.

  |Evaluation steps for metric type `Counter`|
  |-|
  |Execute PromQL expression `sum(rate(total_http_requests{job="cav-demo-app-1-backend-svc",namespace="demo"}[2h]))` to get the evaluated value|
  |Check whether evaluated value <= 0.00005 (the specified `thresholdValue`)|

{{% alert title="Prometheus Metrics Data" color="light" %}}
- Prometheus stores metric data as multiple time series by label set. The number of time series for a single metric depends on the possible label combinations. The `job` label represents the metric source and (within Kubernetes) corresponds to the service representing the workload.
- CAP Operator supports only the `Gauge` and `Counter` Prometheus metric types. Learn more about metric types [here](https://prometheus.io/docs/concepts/metric_types/).
{{% /alert %}}

All specified metrics of a workload must satisfy the evaluation criteria for the workload to be eligible for cleanup.

#### Deletion Rules (Variant 2) as a PromQL expression

You can also specify deletion criteria for a workload by providing a PromQL expression that returns a boolean scalar.
```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  namespace: demo
  name: cav-demo-app-1
spec:
  workloads:
    - name: backend
      deploymentDefinition:
        monitoring:
          deletionRules:
            expression: scalar(sum(avg_over_time(current_sessions{job="cav-demo-app-1-backend-svc",namespace="demo"}[2h]))) <= bool 5
```

The PromQL expression is executed as a Prometheus query. The expected result is a scalar boolean (`0` or `1`). Use [comparison binary operators](https://prometheus.io/docs/prometheus/latest/querying/operators/#comparison-binary-operators) with the `bool` modifier to produce the expected result. If the evaluation result is true (`1`), the workload is eligible for removal.

This variant is useful when:
- the predefined metric-type evaluation is insufficient for determining workload usage.
- custom scraping configurations are used where the `job` label in the collected time series data does not match the name of the Kubernetes Service created for the workload.

### Scrape Configuration

[Prometheus Operator](https://prometheus-operator.dev/docs/getting-started/introduction/) is a popular Kubernetes operator for managing Prometheus and related monitoring components. A common way to set up scrape targets is by creating the [`ServiceMonitor`](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.ServiceMonitor) resource, which specifies which services (and ports) to scrape for application metrics.

{{% alert title="Prerequisite" color="info" %}}
The `scrapeConfig` feature is available only when the [`ServiceMonitor`](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.ServiceMonitor) custom resource is available on the Kubernetes cluster.
{{% /alert %}}

CAP Operator can automatically create `ServiceMonitor` resources targeting the services created for version workloads. The following sample shows how to configure this.
```yaml
kind: CAPApplicationVersion
metadata:
  namespace: demo
  name: cav-demo-app-1
spec:
  workloads:
    - name: backend
      deploymentDefinition:
        ports:
          - appProtocol: http
            name: metrics-port
            networkPolicy: Cluster
            port: 9000
        monitoring:
          deletionRules:
            expression: scalar(sum(avg_over_time(current_sessions{job="cav-demo-app-1-backend-svc",namespace="demo"}[2h]))) <= bool 5
          scrapeConfig:
            interval: 15s
            path: /metrics
            port: metrics-port
```

With this configuration, CAP Operator creates a `ServiceMonitor` targeting the workload service. The `scrapeConfig.port` must match the name of one of the ports specified on the workload.

{{% alert title="Use Case" color="secondary" %}}
The `scrapeConfig` feature is designed for a minimal configuration that covers the most common use case (scraping the workload service via a defined port). For more complex `ServiceMonitor` configurations, create them separately. If `scrapeConfig` is empty, CAP Operator will not create the related `ServiceMonitor`.
{{% /alert %}}

## Evaluating `CAPApplicationVersions` for cleanup

At specified intervals (controlled by the controller environment variable `METRICS_EVAL_INTERVAL`), CAP Operator selects versions as candidates for evaluation.
- Only versions for `CAPApplications` with the annotation `sme.sap.com/enable-cleanup-monitoring` are considered.
- Versions with a `spec.version` higher than the highest `Ready` version are excluded from evaluation. If no version has `Ready` status, no versions are evaluated.
- Versions linked to a `CAPTenant` are excluded. This includes versions referenced by the following `CAPTenant` fields:
  - `status.currentCAPApplicationVersionInstance` — the tenant's current version.
  - `spec.version` — the version a tenant is upgrading to.

Workloads from the identified versions are then evaluated against their `deletionRules`. Workloads without `deletionRules` are automatically eligible for cleanup. All deployment workloads of a version must satisfy the evaluation criteria for the version to be deleted.
