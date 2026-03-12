---
title: "Troubleshooting"
linkTitle: "Troubleshooting"
weight: 90
type: "docs"
description: >
  Common issues and how to solve them
---

### Usage of @sap/cds-mtxs library for multitenancy

> The CAP Operator uses the `@sap/cds-mtxs` library. Prior to version 0.7.0, you could disable this by setting the `IS_MTXS_ENABLED` environment variable to `"false"` in the `TenantOperation` workload, which used the older `@sap/cds-mtx` library-based wrapper job instead. This is no longer supported and has been removed, as support for CDS v6 has ended.

CAP Operator uses `@sap/cds-mtxs` (which replaces the former `@sap/cds-mtx` library) by default. This enables built-in CLI-based handling for tenant provisioning, deprovisioning, and upgrade operations.

Depending on your Kubernetes cluster hardening setup, you may need to add a `securityContext` to the `TenantOperation` and `CAP` workloads, as shown below.

``` yaml
 - name: tenant-job
    consumedBTPServices:
    - "{{ include "xsuaaInstance" . }}"
    - "{{ include "serviceManagerInstance" . }}"
    - "{{ include "saasRegistryInstance" . }}"
    jobDefinition:
      type: TenantOperation
      env:
      - name: CDS_ENV
        value: production
      - name: CDS_CONFIG
        value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
      image: "some.repo.example.com/cap-app/server"
      securityContext: # needed until CAP resolves issue with folder creation in the root dir of the app container at runtime
        runAsUser: 1000
```

### Secret and credential handling for CAP Operator workloads

Libraries like `xsenv`/`cds` (CAP) handle credentials differently across environments (CF vs Kubernetes). On Kubernetes, when credential data is read directly from secrets, JSON data type information may be lost, leading to inconsistencies.

This is addressed by the SAP Service Binding Specification, which requires metadata to be added to secrets. Both `btp-service-operator` and `cf-service-operator` support this metadata addition. If this feature is not used in your cluster, CAP Operator avoids inconsistencies by creating a `VCAP_SERVICES` environment variable across all workloads and expects all SAP BTP service credentials to be stored in Kubernetes Secrets under a `credentials` key.

You can achieve this using the `secretKey` property when creating a `ServiceBinding` with `btp-service-operator` or `cf-service-operator`:

```yaml
apiVersion: cf.cs.sap.com/v1alpha1
kind: ServiceBinding
metadata:
  name: uaa
  namespace: demo
spec:
  serviceInstanceName: uaa
  name: app-uaa
  secretKey: credentials
```

> We recommend using `secretKey` even when credential metadata is available, to reduce the overhead of parsing multiple JSON attributes.

### HTTP requests to the AppRouter are not forwarded to the application server

The AppRouter maps incoming requests to configured destinations. If you use an `xs-app.json` file to specify route mappings to various destinations, ensure that the `destinationName` property for the CAP back end is specified in the corresponding `CAPApplicationVersion` configuration. CAP Operator injects this destination into the AppRouter pods via environment variables.


### HTTP requests time out in the AppRouter for long-running back-end operations

If your back-end service takes a long time to respond, configure the `destinations` environment variable on the AppRouter to set the desired timeout for that destination (`destinationName`). CAP Operator overwrites only the URL part of the destination to point to the correct workload; all other settings are preserved as configured.

### Supported AppRouter version

Use `@sap/approuter` version `14.x.x` or higher.

### CAP Operator resources cannot be deleted

All custom resources (CRs) created by CAP Operator are protected with `finalizers` to ensure proper cleanup. For example, when deleting a `CAPApplication`, all existing tenants are automatically deprovisioned to avoid inconsistencies. Once deprovisioning completes, the corresponding CRs are removed automatically. The provider `CAPTenant` resource cannot be deleted before the associated `CAPApplication` is deleted.

> **Important**: CAP Operator requires the secrets from service instances and bindings to exist for the entire lifecycle of the application. Removing service instances, bindings, or their secrets from the cluster while CAP application CRs still exist will leave orphaned resources (and potentially orphaned database data), and recovery from such inconsistent states may not be possible.
>
> This situation can easily occur when using `helm uninstall`, since the deletion order of resources is not configurable. Ensure that secrets from service instances and bindings are not deleted before all CAP application resources that depend on them are fully removed.
