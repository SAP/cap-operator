---
title: "CAPTenantOperation"
linkTitle: "CAPTenantOperation"
weight: 40
type: "docs"
description: >
  How to configure the `CAPTenantOperation` resource
---

{{< alert color="warning" title="Warning" >}}
The `CAPTenantOperation` resource is managed by CAP Operator and must not be created or modified manually. The creation of `CAPTenantOperation` is initiated by the `CAPTenant` for executing provisioning, deprovisioning, or upgrade.
{{< /alert >}}

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenantOperation
metadata:
  name: cap-app-consumer-ge455-77kb9
  namespace: cap-ns
spec:
  capApplicationVersionInstance: cav-cap-app-v2
  operation: upgrade
  steps:
    - continueOnFailure: true
      name: mtx-runner
      type: CustomTenantOperation
    - name: mtx-runner
      type: TenantOperation
    - name: create-test-data
      type: CustomTenantOperation
  subDomain: consumer-x
  tenantId: cb46733-1279-48be-fdf434-aa2bae55d7b5
```

The example above shows a `CAPTenantOperation` created to execute an upgrade operation on a tenant. In addition to tenant details, the `CAPApplicationVersion` to be used for the operation is specified. In case of upgrade or a provisioning operation, this would be the target `CAPApplicationVersion` whereas for deprovisioning, it would be the current `CAPApplicationVersion` of the tenant.

The operation is completed by executing a series of steps (jobs) which are specified in or derived from the `CAPApplicationVersion`. Each step refers to a workload of type `TenantOperation` or `CustomTenantOperation`. When `CAPTenantOperation` is created by CAP Pperator, there must be at least one step of type `TenantOperation` (which is the job used for the database schema update using CAP provided modules).

`CustomTenantOperation` jobs are hooks provided to the application, which can be executed before or after the actual `TenantOperation`. For applications to be able to identify the context of an execution, each job is injected with the following environment variables:

- `CAPOP_APP_VERSION`: The (semantic) version from the relevant `CAPApplicationVersion`
- `CAPOP_TENANT_ID`: Tenant identifier of the tenant for which the operation is executed
- `CAPOP_TENANT_OPERATION`: The type of operation - `provisioning`, `deprovisioning`, or `upgrade`
- `CAPOP_TENANT_SUBDOMAIN`: Subdomain (from subaccount) belonging to the tenant for which the operation is executed
