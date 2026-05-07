---
title: "Tenant Subscription"
linkTitle: "Tenant Subscription"
weight: 30
type: "docs"
description: >
  How tenant provisioning works
---

In CAP Operator, a valid tenant for an application is represented by the `CAPTenant` resource. It references the `CAPApplication` it belongs to and specifies the details of the SAP BTP subaccount that represents the tenant.

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

Tenant provisioning begins when a consumer subaccount subscribes to the application, either via the SAP BTP cockpit or using the SaaS Provisioning service APIs. This triggers an asynchronous callback from the SaaS Provisioning service into the cluster, which is handled by the [subscription server](../../concepts/operator-components/subscription-server). The subscription server validates the request and creates a `CAPTenant` instance for the identified `CAPApplication`.

{{% alert color="warning" title="Warning" %}}
`CAPTenant` instances must not be created or deleted manually. They are managed exclusively by the subscription server in response to provisioning calls from the SaaS Provisioning service.
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

The `CAPTenantOperation` is reconciled to create Kubernetes Jobs (steps) derived from the latest `CAPApplicationVersion` in `Ready` state. The steps include a `TenantOperation` job and optional `CustomTenantOperation` steps. The `TenantOperation` step uses built-in CLI-based tenant operations from `@sap/cds-mtxs` to execute tenant provisioning.

The `CAPTenant` reaches a `Ready` state only after:

- All `CAPTenantOperation` steps complete successfully, and
- An Istio `VirtualService` is created to route HTTP requests on the tenant subdomain to the application.

![tenant-provisioning](/cap-operator/img/activity-tenantprovisioning.drawio.svg)

### Get Dependencies

During provisioning, the SaaS Provisioning service calls a `getDependencies` endpoint to retrieve the list of reuse services that the multitenant application requires. The CAP Operator subscription server exposes this endpoint and resolves dependencies by inspecting the BTP services defined in the `CAPApplication`.

The subscription server exposes the following endpoint:

```
GET /dependencies/{providerSubaccountId}/{appName}/
```

The `providerSubaccountId` and `appName` path parameters identify the corresponding `CAPApplication` resource. The system authorizes the request using the same mechanism as the provisioning endpoints (Bearer token).

{{% alert color="info" title="Note" %}}
The `appName` value in the URL must match `spec.btpAppName` of the `CAPApplication` resource. Because it is also registered with the SaaS Provisioning service, it should follow the service's `xsappname` conventions.
{{% /alert %}}

A successful response returns a JSON array of objects. Each object contains the `xsappname` of a qualifying service:

```json
[
  { "xsappname": "my-destination-service!b42" },
  { "xsappname": "my-auditlog-service!b7" }
]
```

#### Service Qualification

The subscription server iterates over all BTP services listed in `CAPApplication.spec.btp.services`. For each service, it reads the associated Kubernetes secret, parses the credentials, and determines whether to include the service in the response.

The `xsappname` is read from either the top-level `xsappname` field or the nested `uaa.xsappname` field in the service credentials. If not found, the service is excluded from the response.

#### Configuring Dependencies with `subscriptionDependency`

Each entry in `spec.btp.services` can include an optional `subscriptionDependency` field that controls whether the service is included:

| Value | Behaviour |
|---|---|
| `Auto` (default) | The operator determines inclusion based on service class and credentials (see below) |
| `Always` | Includes the service regardless of class |
| `Never` | Excludes the service regardless of class or credentials |

```yaml
spec:
  btp:
    services:
      - name: my-destination
        class: destination
        secret: my-destination-secret
        subscriptionDependency: Always   # force inclusion
      - name: my-xsuaa
        class: xsuaa
        secret: my-xsuaa-secret
        subscriptionDependency: Never    # force exclusion
      - name: my-auditlog
        class: auditlog
        secret: my-auditlog-secret
        # subscriptionDependency omitted → Auto
```

**`Auto` qualification rules**

When `subscriptionDependency` is set to `Auto` or omitted, the system includes the service if any of the following conditions apply:

- The service credentials contain `"saasregistryenabled": true`
- Service `class` is `destination`
- Service `class` is `connectivity`
- Service `class` is `auditlog` **and** the credential `plan` is `oauth2`

This behavior aligns with the implementation in the [`@sap/approuter`](https://www.npmjs.com/package/@sap/approuter) package.

### Tenant Deprovisioning

When a tenant unsubscribes from the application, the subscription server receives the request, validates the existence and status of the `CAPTenant`, and submits a deletion request to the Kubernetes API server.

The controller identifies the pending deletion but defers it until a `CAPTenantOperation` of type `deprovisioning` is created and completes successfully. The `CAPTenantOperation` creates the corresponding Jobs (steps) that execute the tenant deprovisioning.
