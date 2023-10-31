---
title: "CAPTenant"
linkTitle: "CAPTenant"
weight: 30
type: "docs"
description: >
  How to configure the `CAPTenant` resource
---

{{< alert color="warning" title="Warning" >}}
The `CAPTenant` resource is completely managed by CAP Operator and must not be created or modified manually. For details of how `CAPTenant` is created, see [tenant subscription](../../tenant-provisioning).
{{< /alert >}}

The `CAPTenant` resource indicates the existence of a tenant in the related application (or one that is current being provisioned). The resource starts with a `Provisioning` state and moves to `Ready` when successfully provisioned. Managing tenants as Kubernetes resources allows you not only to control the lifecycle of the entity, but also allows you to control other requirements that must be fulfilled for the application to serve tenant-specific requests (for example, creating of networking resources).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenant
metadata:
  name: cap-app-consumer-ge455
  namespace: cap-ns
spec:
  capApplicationInstance: cap-app
  subDomain: consumer-x
  tenantId: cb46733-1279-48be-fdf434-aa2bae55d7b5
  version: "1"
  versionUpgradeStrategy: always
```

The specification contains attributes relevant for SAP BTP, which identifies a tenant such as `tenantId` and `subDomain`.

The `version` field corresponds to the `CAPApplicationVersion` on which the tenant is provisioned or was upgraded. When a newer `CAPApplicationVersion` is available, the operator automatically increments the tenant version, which triggers the upgrade process. The `versionUpgradeStrategy` is by default `always`, but can be set to `none` in exceptional cases to prevent an automatic upgrade of the tenant.
