---
title: "What's New"
linkTitle: "What's New"
weight: 20
description: >
  Discover new features added to CAP Operator
---

### New updates

{{% cardpane %}}
  {{% card header="Q4 2025" %}}
  CAP Operator now allows any deployment workload to be exposed as a service. Learn more about [Service Exposure](./usage/service-exposure).
  {{% /cardpane %}}
  {{% card header="Q2 2025" %}}
  CAP Operator now has enhanced Domain Management features. Learn more about [Domain Management](./usage/domain-management).
  {{% /card %}}
  {{% card header="Q1 2025" %}}
  CAP Operator now supports `Services Only` applications that are tenant agnostic. Learn more about [Services Only Applications](./usage/service-exposure/#deploying-services-only-applications).
  {{% /card %}}
{{% /cardpane %}}


### Former updates

{{% cardpane %}}
  {{% card header="Q4 2024" %}}
  CAP Operator now emits prometheus metrics for [Controller](docs/concepts/operator-components/controller/) and [Subscription Server](docs/concepts/operator-components/subscription-server/) components. Learn more about [metrics](./usage/operator-metrics).
  {{% /card %}}
  {{% card header="Q3 2024" %}}
  Define monitoring configuration on version workloads which allow outdated versions to be automatically cleaned up based on usage. Learn more about [Version Monitoring](./usage/version-monitoring).
  {{% /card %}}
  {{% card header="Q3 2024" %}}
  New Custom Resource `CAPTenantOutput` can be used to record subscription related data from tenant operations. [Learn more](./usage/resources/captenantoutput).
  {{% /card %}}
  {{% card header="Q2 2024" %}}
  `CAPApplicationVersion` now supports configuration of `initContainers`, `volumes`, `serviceAccountName`, [scheduling related configurations](https://kubernetes.io/docs/concepts/scheduling-eviction/) etc. on workloads.
  {{% /card %}}
{{% /cardpane %}}
