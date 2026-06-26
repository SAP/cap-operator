---
title: "What's New"
linkTitle: "What's New"
weight: 20
description: >
  Discover the latest features and improvements in CAP Operator
---

### Recent updates

{{% cardpane %}}
  {{% card header="Rollout on Credential Update" %}}
  CAP Operator now triggers a rollout of relevant workloads when credentials (service bindings) are updated. Learn more about [Rollout on Credential Update](../usage/rollout-on-credential-update).
  {{% /card %}}
  {{% card header="Omit Provider" %}}
  As of version 0.31.0, the provider section in `CAPApplication` is deprecated and can be omitted entirely, even for multi-tenant applications. Omitting it also skips the creation of a provider tenant.
  {{% /card %}}
  {{% card header="Subscription - getDependencies" %}}
  The subscription server now supports the `getDependencies` callback, enabling CAP applications to return dependencies during tenant subscription. Learn more about [getDependencies support](../usage/tenant-provisioning/#get-dependencies).
  {{% /card %}}
{{% /cardpane %}}


### Previous updates

{{% cardpane %}}
  {{% card header="Service Exposure" %}}
  CAP Operator now allows any deployment workload to be exposed as a service. Learn more about [Service Exposure](../usage/service-exposure).
  {{% /card %}}
  {{% card header="Domain Management" %}}
  CAP Operator now includes enhanced domain management features. Learn more about [Domain Management](../usage/domain-management).
  {{% /card %}}
  {{% card header="Services-Only Applications" %}}
  CAP Operator now supports `Services Only` applications that are tenant-agnostic. Learn more about [Services-Only Applications](../usage/service-exposure/#deploying-services-only-applications).
  {{% /card %}}
{{% /cardpane %}}


