---
title: "CAPTenantOperation"
linkTitle: "CAPTenantOperation"
weight: 40
type: "docs"
description: >
  How to configure the `CAPTenantOperation` resource
---

{{% alert color="warning" title="Warning" %}}
The `CAPTenantOperation` resource is managed by CAP Operator and must not be created or modified manually. It is created by the `CAPTenant` to execute provisioning, deprovisioning, or upgrade operations.
{{% /alert %}}

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
      name: tenant-operation
      type: CustomTenantOperation
    - name: tenant-operation
      type: TenantOperation
    - name: create-test-data
      type: CustomTenantOperation
  subDomain: consumer-x
  tenantId: cb46733-1279-48be-fdf434-aa2bae55d7b5
```

The example above shows a `CAPTenantOperation` for an upgrade operation. In addition to tenant details, it specifies the `CAPApplicationVersion` to use. For upgrade and provisioning operations, this is the target version; for deprovisioning, it is the tenant's current version.

The operation executes a series of steps (jobs) specified in or derived from the `CAPApplicationVersion`. Each step refers to a workload of type `TenantOperation` or `CustomTenantOperation`. When CAP Operator creates a `CAPTenantOperation`, at least one step of type `TenantOperation` must be present (this is the job that performs the database schema update using CAP-provided modules).

`CustomTenantOperation` jobs are hooks that the application can execute before or after the `TenantOperation`. To help applications identify the execution context, each job receives the following environment variables:

- `CAPOP_APP_VERSION`: The semantic version from the relevant `CAPApplicationVersion`
- `CAPOP_TENANT_ID`: The tenant identifier
- `CAPOP_TENANT_OPERATION`: The operation type — `provisioning`, `deprovisioning`, or `upgrade`
- `CAPOP_TENANT_SUBDOMAIN`: The subdomain (from the subaccount) of the tenant
- `CAPOP_TENANT_TYPE`: The tenant type — `provider` or `consumer`
- `CAPOP_APP_NAME`: The BTP app name from the corresponding `CAPApplication`
- `CAPOP_GLOBAL_ACCOUNT_ID`: The global account identifier from the corresponding `CAPApplication`
- `CAPOP_PROVIDER_TENANT_ID`: The provider tenant identifier from the corresponding `CAPApplication`
- `CAPOP_PROVIDER_SUBDOMAIN`: The provider tenant subdomain from the corresponding `CAPApplication`

All of the above environment variables are also available on the corresponding `initContainers`, along with relevant `VCAP_SERVICES` credentials.
