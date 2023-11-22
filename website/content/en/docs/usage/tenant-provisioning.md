---
title: "Tenant Subscription"
linkTitle: "Tenant Subscription"
weight: 30
type: "docs"
description: >
  How tenant provisioning works
---

From the perspective of CAP Operator, a valid tenant for an application is represented by the resource `CAPTenant`. It refers to the `CAPApplication` it belongs to and specifies the details of the SAP BTP subaccount representing the tenant.

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

## Tenant Provisioning

The process of tenant provisioning starts when a consumer subaccount subscribes to the application, either via the SAP BTP cockpit or using the APIs provided by the SaaS provisioning service. This, in turn, initiates the asynchronous callback from the SaaS provisioning service instance into the cluster, and the request is handled by the [subscription server]({{< ref "docs/concepts/operator-components/subscription-server.md" >}}). The subscription server validates the request and creates an instance of `CAPTenant` for the identified `CAPApplication`.

{{< alert color="warning" title="Warning" >}}
An instance of `CAPTenant` must not be created or deleted manually within the cluster. A new instance has to be created by the subscription server after receiving a provisioning call from SaaS provisioning service.
{{< /alert >}}

The controller, observing the new `CAPTenant`, will initiate the provisioning process by creating the resource `CAPTenantOperation`, which represents the provisioning operation.

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
    - name: cap-backend # <-- derived from workload of type CAP (when workload of type TenantOperation is not specified)
      type: TenantOperation
```

The `CAPTenantOperation` is further reconciled to create Kubernetes jobs (steps), which are derived from the latest `CAPApplicationVersion`, which is in `Ready` state. The steps comprise of a `TenantOperation` job and optional `CustomTenantOperation` steps. The `TenantOperation` step uses built in CLI-based tenant operations from `@sap/cds-mtxs` to execute tenant provisioning.

The `CAPTenant` reaches a `Ready` state, only after

- a successful completion of all `CAPTenantOperation` steps.
- the creation of Istio `VirtualService`, which allows HTTP requests on the tenant subdomain to reach the application.

![tenant-provisioning](/cap-operator/img/activity-tenantprovisioning.drawio.svg)

## Tenant Deprovisioning

Similar to the tenant provisioning process, when a tenant unsubscribes from the application, the request is received by the subscription server. It validates the existence and status of the `CAPTenant` and submits a request for deletion to the Kubernetes API server.

The controller identifies that the `CAPTenant` has to be deleted, but withholds deletion until it can create and watch for a successful completion of a `CAPTenantOperation` of type deprovisioning. The `CAPTenantOperation` creates the corresponding jobs (steps), which execute the tenant deprovisioning.
