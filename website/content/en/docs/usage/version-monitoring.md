---
title: "Version Monitoring"
linkTitle: "Version Monitoring"
weight: 50
type: "docs"
description: >
  How to monitor versions for automatic cleanup
---

In a continuous delivery environment where newer applications versions may be deployed frequently, monitoring and cleaning up older unused versions becomes important to conserve cluster resources (compute, memory, storage etc.) and operate a clutter free system. The CAP Operator now provides application developers and operations teams to define how an application version can be monitored for usage.

## Integration with Prometheus

[Prometheus](https://prometheus.io/) is the industry standard for monitoring application metrics and provides a wide variety of tools for managing and reporting metrics data. The CAP Operator (controller) can be connected to a [Prometheus](https://prometheus.io/) server by setting the `PROMETHEUS_ADDRESS` environment variable on the controller (see [Configuration](../configuration/_index.md)). The controller is then able to query application related metrics based on the workload specification of `CAPApplicationVersions`. If no Prometheus address is supplied, the version monitoring function of the controller is not started.

## Configure `CAPApplication`

To avoid incompatible changes, version cleanup monitoring must be enabled for CAP application using the annotation `sme.sap.com/enable-cleanup-monitoring`. The annotation can have the following values which affects the version cleanup behavior:

|Value|Behavior|
|--|--|
|`dry-run`|When a `CAPApplicationVersion` is evaluated to be eligible for cleanup, an event of type `ReadyForDeletion` is emitted without performing the actual deletion of the version.|
|`true`|When a `CAPApplicationVersion` is evaluated to be eligible for cleanup, the version is deleted and an event of type `ReadyForDeletion` is emitted.|

## Configure `CAPApplicationVersion`

For each _workload of type deployment_ in a `CAPApplicationVersion`, it is possible to define:
1. Deletion rules: A criteria based on metrics which when satisfied signifies that the workload can be removed
2. Scrape configuration: Configuration which defines how metrics are scraped from the workload service.

#### Deletion Rules (Variant 1) based on Metric Type

The following example shows how a workload, named `backend`, is configured with deletion rules based on multiple metrics.
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
This informs the CAP Operator that workload `backend` is supplying two metrics which can be monitored for usage.

- Metric `current_sessions` is of type `Gauge` which indicates that it is an absolute value at any point of time. When evaluating this metric, the CAP operator queries Prometheus with a PromQL expression which calculates the average value of this metric over a specified calculation period. The average value from each time series is then added together to get the evaluated value. The evaluated value is then compared against the specified threshold value to determine usage (or eligibility for cleanup).
  
  |Evaluation steps for metric type `Gauge`|
  |-|
  |Execute PromQL expression `sum(avg_over_time(current_sessions{job="cav-demo-app-1-backend-svc",namespace="demo"}[90m]))` to get the evaluated value|
  |Check whether evaluated value <= 0 (the specified `thresholdValue`)|

- Similarly, metric `total_http_requests` is of type `Counter` which indicates that it is a cumulative value which can increment. When evaluating this metric, the CAP operator queries Prometheus with a PromQL expression which calculates the rate (of increase) of this metric over a specified calculation period. The rate of increase from each time series is then added together to get the evaluated value. The evaluated value is then compared against the specified threshold value to determine usage (or eligibility for cleanup).
  
  |Evaluation steps for metric type `Counter`|
  |-|
  |Execute PromQL expression `sum(rate(total_http_requests{job="cav-demo-app-1-backend-svc",namespace="demo"}[2h]))` to get the evaluated value|
  |Check whether evaluated value <= 0.00005 (the specified `thresholdValue`)|

{{% alert title="Prometheus Metrics Data" color="light" %}}
- Prometheus stores metric data as multiple time series by label set. The number of time series created from a single metric depends on the possible combination of labels. The label `job` represents the source of the metric and (within Kubernetes) is the service representing the workload.
- CAP Operator does not support Prometheus metric types other than `Gauge` and `Counter`. Lean more about metric types [here](https://prometheus.io/docs/concepts/metric_types/).
{{% /alert %}}

All specified metrics of a workload must satisfy the evaluation criteria for the workload to be eligible for cleanup.

#### Deletion Rules (Variant 2) as PromQL expression

Another way to specify the deletion criteria for a workload is by providing a PromQL expression which results a boolean scalar.
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

The supplied PromQL expression is executed as a Prometheus query by the CAP Operator. The expected result is a scalar boolean (`0` or `1`). Users may use [comparison binary operators](https://prometheus.io/docs/prometheus/latest/querying/operators/#comparison-binary-operators) with the `bool` modifier to achieve the expected result. If the evaluation result is true (`1`), the workload is eligible for removal.

This variant can be useful when:
- the predefined evaluation based on metric types is not enough for determining usage of a workload.
- custom metrics scraping configurations are employed where the `job` label in the collected time series data does not mach the name of the (Kubernetes) Service created for the workload.

### Scrape Configuration

[Prometheus Operator](https://prometheus-operator.dev/docs/getting-started/introduction/) is a popular Kubernetes operator for managing Prometheus and related monitoring components. A common way to setup scrape targets for a Prometheus instance is by creating the [`ServiceMonitor`](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.ServiceMonitor) resource which specifies which `Services` (and ports) that should be scraped for collecting application metrics.

{{% alert title="Prerequisite" color="info" %}}
The `scrapeConfig` feature of a workload is usable only when the [`ServiceMonitor`](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.ServiceMonitor) Custom Resource is available on the Kubernetes cluster.
{{% /alert %}}

The CAP Operator provides an easy way to create `Service Monitors` which target the `Services` created for version workloads. The following sample shows how to configure this.
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

With this configuration the CAP Operator will create a `ServiceMonitor` which targets the workload `Service`. The `scrapeConfig.port` should match the name of one of the ports specified on the workload.

{{% alert title="Use Case" color="secondary" %}}
The workload `scrapeConfig` aims to support a minimal configuration, creating a `ServiceMonitor` which supports the most common use case (i.e. scraping the workload service via. a defined workload port). To use complex configurations in `ServiceMonitors`, they should be created separately. If the `scrapeConfig` of a version workload is empty, the CAP Operator will not attempt to create the related `ServiceMonitor`. 
{{% /alert %}}

## Evaluating `CAPApplicationVersions` for cleanup

At specified intervals (dictated by controller environment variable `METRICS_EVAL_INTERVAL`), the CAP Operator selects versions which are candidates for evaluation.
- Only versions for `CAPApplications` where annotation `sme.sap.com/enable-cleanup-monitoring` is set are considered.
- All versions (`spec.version`) higher than the highest version with `Ready` status are not considered for evaluation. If there is no version with status `Ready`, no versions are considered.
- All versions linked to a `CAPTenant` are excluded from evaluation. This includes versions where the following fields of a `CAPTenant` point to the version:
  - `status.currentCAPApplicationVersionInstance` - current version of the tenant.
  - `spec.version` - the version to which a tenant is upgrading.

Workloads from the identified versions are then evaluated based on the defined `deletionRules`. Workloads without `deletionRules` are automatically eligible for cleanup. All workloads (with type deployment) of a version must satisfy the evaluation criteria for the version to be deleted.

