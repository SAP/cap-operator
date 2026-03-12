---
title: "Tenant Subscription"
linkTitle: "Tenant Subscription"
weight: 30
type: "docs"
description: >
  How tenant provisioning works
---

In CAP Operator, a valid tenant for an application is represented by the `CAPTenant` resource. It references the `CAPApplication` it belongs to and specifies the details of the SAP BTP subaccount representing the tenant.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenant
metadata:
  name: cap-app-01-provider
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-app-01 # <-- reference to the CAPApplication
  subDomain: app-provider
  tenantId: aa2bae55d7b5-1279-456564-a7b0-aa2bae55d7b5
  version: "1.0.0" # <-- expected version of the application
  versionUpgradeStrategy: always # <-- always / never
```

### Tenant Provisioning

Tenant provisioning begins when a consumer subaccount subscribes to the application, either via the SAP BTP cockpit or using the SaaS provisioning service APIs. This triggers an asynchronous callback from the SaaS provisioning service into the cluster, which is handled by the [subscription server](../../concepts/operator-components/subscription-server). The subscription server validates the request and creates a `CAPTenant` instance for the identified `CAPApplication`.

{{% alert color="warning" title="Warning" %}}
`CAPTenant` instances must not be created or deleted manually. They are managed exclusively by the subscription server in response to provisioning calls from the SaaS provisioning service.
{{% /alert %}}

The controller, observing the new `CAPTenant`, initiates the provisioning process by creating a `CAPTenantOperation` resource representing the provisioning operation.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenantOperation
metadata:
  name: cap-app-01-provider-sgz8b
  namespace: cap-app-01
spec:
  capApplicationVersionInstance: cav-cap-app-01-1 # <-- latest CAPApplicationVersion in Ready state
  subDomain: app-provider
  tenantId: aa2bae55d7b5-1279-456564-a7b0-aa2bae55d7b5
  operation: provisioning # <-- valid values are provisioning, deprovisioning and upgrade
  steps:
    - name: cap-backend # <-- derived from workload of type CAP (used when no TenantOperation workload is specified)
      type: TenantOperation
```

The `CAPTenantOperation` is reconciled to create Kubernetes jobs (steps) derived from the latest `CAPApplicationVersion` in `Ready` state. The steps include a `TenantOperation` job and optional `CustomTenantOperation` steps. The `TenantOperation` step uses built-in CLI-based tenant operations from `@sap/cds-mtxs` to execute tenant provisioning.

The `CAPTenant` reaches a `Ready` state only after:

- all `CAPTenantOperation` steps complete successfully, and
- an Istio `VirtualService` is created to route HTTP requests on the tenant subdomain to the application.

![tenant-provisioning](/cap-operator/img/activity-tenantprovisioning.drawio.svg)

### Tenant Deprovisioning

When a tenant unsubscribes from the application, the subscription server receives the request, validates the existence and status of the `CAPTenant`, and submits a deletion request to the Kubernetes API server.

The controller identifies the pending deletion but withholds it until a `CAPTenantOperation` of type `deprovisioning` is created and completes successfully. The `CAPTenantOperation` creates the corresponding jobs (steps) that execute the tenant deprovisioning.
