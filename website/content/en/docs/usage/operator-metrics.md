---
title: "Operator Metrics"
linkTitle: "Operator Metrics"
weight: 60
type: "docs"
description: >
  How to monitor and consume metrics emitted by CAP Operator
---

The [Controller](docs/concepts/operator-components/controller/) and [Subscription Server](docs/concepts/operator-components/subscription-server/) now emit [Prometheus metrics](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus) at `/metrics` path and `9090` port that may be used by consumers to analyze and understand usage, detect potential issues, monitor and scale cluster resources.
You can enable

### Controller metrics
The controller emits [standard go metrics](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/collectors#WithGoCollectorRuntimeMetrics), workqueue metrics for the resources being reconciled implemented based on [MetricsProvider](https://pkg.go.dev/k8s.io/client-go/util/workqueue#MetricsProvider) and the following additional metrics:

{{% pageinfo %}}
```
cap_op_reconcile_errors{kind="CAPApplication",name="my-app",namespace="app"} 11
```
a counter type metric indicating total resources that failed to reconcile for each Kind.

---

```
cap_op_tenant_operations{app="<hash>",operation="provisioning"} 83
```
a counter type metric that provides some insights into the overall number of tenant operations.
{{% /pageinfo %}}

By setting the enviroment variable `DETAILED_OPERATIONAL_METRICS` to `"true"`, one can optionally also see these detailed operational metrics:

{{% pageinfo %}}
```
cap_op_tenant_operation_failures{app="<hash>",operation="upgrade",tenant_id="<guid>",namespace="app",name="my-app-tenant-op-xxyyz"} 2
```
a counter type metric that provides some insights into failed tenant operations per app, tenant along with name and namespace details of the failed operation resource.

---

```
cap_op_last_tenant_operation_duration_seconds{app="<hash>",tenant_id="<guid>"} 42
```
a guage type metric that provides some info about the duration in seconds taken by the last tenant operation for an app and tenant.
{{% /pageinfo %}}


### Subscription Server metrics
The controller emits [standard go metrics](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/collectors#WithGoCollectorRuntimeMetrics), and the following http handler specific metrics:

{{% pageinfo %}}
```
cap_op_subscription_requests_total{code="202",method="POST"} 82
```
a counter type metric indicating total requests triggered for susbscription based on http method and response code.

---

```
cap_op_subscription_requests_inflight{} 1
```
a guage type metric indicating the subscription requests currently being processed by the handler.
{{% /pageinfo %}}