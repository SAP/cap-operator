---
title: "What's New"
linkTitle: "What's New"
weight: 20
description: >
  Discover new features added to CAP Operator
---

{{% cardpane %}}
  {{% card header="Q3 2024" %}}
  Define monitoring configuration on version workloads which allow outdated versions to be automatically cleaned up based on usage. Learn more about [Version Monitoring](./usage/version-monitoring.md).
  {{% /card %}}
  {{% card header="Q3 2024" %}}
  New Custom Resource `CAPTenantOutput` can be used to record subscription related data from tenant operations. [Learn more](./usage/resources/captenantoutput.md).
  {{% /card %}}
  {{% card header="Q2 2024" %}}
  `CAPApplicationVersion` now supports configuration of `initContainers`, `volumes`, `serviceAccountName`, [scheduling related configurations](https://kubernetes.io/docs/concepts/scheduling-eviction/) etc. on workloads.
  {{% /card %}}
{{% /cardpane %}}
