---
title: "Operator Metrics"
linkTitle: "Operator Metrics"
weight: 60
type: "docs"
description: >
  How to monitor and consume metrics emitted by CAP Operator
---

## Overview

The CAP Operator includes built-in [Prometheus metrics](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus) that enable users to effectively monitor and analyze the operator's performance. These metrics can provide insights into resource usage, potential issues, and overall operator health. The metrics are accessible at the `/metrics` endpoint on port `9090` of both the [Controller](docs/concepts/operator-components/controller/) and the [Subscription Server](docs/concepts/operator-components/subscription-server/).

## Controller Metrics

The Controller emits several types of metrics, including:

- **Standard Go Metrics**: These metrics are provided by the [Prometheus Go client](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/collectors#WithGoCollectorRuntimeMetrics) and include runtime statistics.
- **Workqueue Metrics**: These metrics are relevant to the resources being reconciled and are based on the [MetricsProvider](https://pkg.go.dev/k8s.io/client-go/util/workqueue#MetricsProvider).
- Specific metrics: [mentioned below](#specific-metrics).

### Specific Metrics

1. **Reconcile Errors** -- `cap_op_reconcile_errors`, e.g.:
```
cap_op_reconcile_errors{kind="CAPApplication",name="my-app",namespace="app"} 11
```
- **Type**: Counter
- **Description**: This metric tracks the total number of resources that failed to reconcile for each resource kind, such as `CAPApplication`.

2. **Tenant Operations** -- `cap_op_tenant_operations`, e.g.
```
cap_op_tenant_operations{app="<hash>",operation="provisioning"} 83
```
- **Type**: Counter
- **Description**: This metric provides insights into overall tenant operations being performed.

### Detailed Operational Metrics

To gain deeper insights, you can enable more granular metrics by setting the environment variable `DETAILED_OPERATIONAL_METRICS` to `"true"`.

1. **Failed Tenant Operations** -- `cap_op_tenant_operation_failures`, e.g.:
```
cap_op_tenant_operation_failures{app="<hash>",operation="upgrade",tenant_id="<guid>",namespace="app",name="my-app-tenant-op-xxyyz"} 2
```
- **Type**: Counter
- **Description**: This metric reveals the number of failed tenant operations, categorized by application, tenant ID, and specific operation details.

2. **Last Tenant Operation Duration** -- `cap_op_last_tenant_operation_duration_seconds`, e.g.:
```
cap_op_last_tenant_operation_duration_seconds{app="<hash>",tenant_id="<guid>"} 17
```
- **Type**: Gauge
- **Description**: This metric measures the duration (in seconds) of the last tenant operation for a specified application and tenant.

## Subscription Server Metrics

The Subscription Server emits the following metrics:
- **Standard Go Metrics**: These metrics are provided by the [Prometheus Go client](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/collectors#WithGoCollectorRuntimeMetrics) and include runtime statistics.
- Specific metrics: [mentioned below](#specific-metrics-1).

### Specific Metrics

1. **Subscription Requests Total** -- `cap_op_subscription_requests_total`, e.g.:
```
cap_op_subscription_requests_total{code="202",method="POST"} 2024
```
- **Type**: Counter
- **Description**: This metric tracks the total number of subscription requests that were processed, categorized by HTTP method and response code.

2. **Inflight Subscription Requests** -- `cap_op_subscription_requests_inflight`, e.g.:
```
cap_op_subscription_requests_inflight{} 4
```
- **Type**: Gauge
- **Description**: This metric indicates the number of subscription requests currently being processed by the server.

## Conclusion

The CAP Operator provides a rich set of metrics to facilitate monitoring and operational insights. By effectively leveraging these metrics, you can monitor and ensure the reliability and performance of your applications. For further details, consider exploring the Prometheus documentation and integrating these metrics into your monitoring systems.