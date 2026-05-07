---
title: "CAPTenant"
linkTitle: "CAPTenant"
weight: 30
type: "docs"
description: >
  How to configure the `CAPTenant` resource
---

{{% alert color="warning" title="Warning" %}}
The `CAPTenant` resource is completely managed by CAP Operator and must not be created or modified manually. For details of how `CAPTenant` is created, see [tenant subscription](../../tenant-provisioning).
{{% /alert %}}

The `CAPTenant` resource indicates the existence of a tenant in the related application (or one that is currently being provisioned). The resource starts with a `Provisioning` state and moves to `Ready` when successfully provisioned. Managing tenants as Kubernetes resources allows you to control not only the lifecycle of the entity, but also other requirements that must be fulfilled for the application to serve tenant-specific requests (for example, creating networking resources).

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

The specification contains attributes relevant to SAP BTP that identify a tenant, such as `tenantId` and `subDomain`.

The `version` field corresponds to the `CAPApplicationVersion` on which the tenant is provisioned or to which it was upgraded. When a newer `CAPApplicationVersion` is available, the operator automatically increments the tenant version, which triggers the upgrade process. The `versionUpgradeStrategy` defaults to `always`, but can be set to `never` in exceptional cases to prevent automatic upgrades of the tenant.
