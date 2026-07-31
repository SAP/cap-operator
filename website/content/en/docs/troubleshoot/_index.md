---
title: "Troubleshooting"
linkTitle: "Troubleshooting"
weight: 90
type: "docs"
description: >
  Common issues and how to solve them
---

### Usage of @sap/cds-mtxs library for multitenancy

> CAP Operator uses the `@sap/cds-mtxs` library. Prior to version 0.7.0, you could disable this by setting the `IS_MTXS_ENABLED` environment variable to `"false"` in the `TenantOperation` workload, which used the older `@sap/cds-mtx` library-based wrapper job instead. This is no longer supported and has been removed, as support for CDS v6 has ended.

CAP Operator uses `@sap/cds-mtxs` (which replaces the former `@sap/cds-mtx` library) by default. This enables built-in CLI-based handling for tenant provisioning, deprovisioning, and upgrade operations.

Depending on your Kubernetes cluster hardening setup, you may need to add a `securityContext` to the `TenantOperation` and `CAP` workloads as shown below.

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

Libraries like `xsenv`/`cds` (CAP) handle credentials differently across environments (Cloud Foundry vs. Kubernetes). On Kubernetes, when credential data is read directly from Secrets, JSON data type information may be lost, leading to inconsistencies.

This is addressed by the SAP Service Binding Specification, which requires metadata to be added to Secrets. Both `btp-service-operator` and `cf-service-operator` support this metadata addition. If this feature is not used in your cluster, CAP Operator avoids inconsistencies by creating a `VCAP_SERVICES` environment variable across all workloads and expects all SAP BTP service credentials to be stored in Kubernetes Secrets under a `credentials` key.

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

### HTTP requests to the Approuter are not forwarded to the application server

The Approuter maps incoming requests to configured destinations. If you use an `xs-app.json` file to specify route mappings to various destinations, ensure that the `destinationName` property for the CAP back end is specified in the corresponding `CAPApplicationVersion` configuration. CAP Operator injects this destination into the Approuter pods via environment variables.


### HTTP requests time out in the Approuter for long-running back-end operations

If your back-end service takes a long time to respond, configure the `destinations` environment variable on the Approuter to set the desired timeout for that destination (`destinationName`). CAP Operator overwrites only the URL part of the destination to point to the correct workload; all other settings are preserved as configured.

### Supported Approuter version

Use `@sap/approuter` version `14.x.x` or higher.

### CAP Operator resources cannot be deleted

All custom resources (CRs) created by CAP Operator are protected with `finalizers` to ensure proper cleanup. The provider `CAPTenant` resource can be manually deleted after removing the `provider` section from the `CAPApplication` specification.

**As of version 0.34.0**, when a `CAPApplication` is deleted, it enters a `Deleting` state and waits until all existing `CAPTenant` resources are removed before proceeding. Consumer tenants must be cleaned up by unsubscribing from the application (via the SAP BTP cockpit or SaaS Provisioning service APIs), and the provider tenant must be deleted manually (by removing the `provider` section from the `CAPApplication` spec or deleting the `CAPApplication`). Once all tenants are removed, the deletion of the `CAPApplication` and its remaining child resources proceeds automatically.

Prior to version 0.34.0, deleting a `CAPApplication` automatically triggered deprovisioning of all existing tenants.

> **Important**: CAP Operator requires the Secrets from service instances and bindings to exist for the entire lifecycle of the application. Removing service instances, bindings, or their Secrets from the cluster while CAP application CRs still exist will leave orphaned resources (and potentially orphaned database data), and recovery from such inconsistent states may not be possible.
>
> This situation can easily occur when using `helm uninstall`, since the deletion order of resources is not configurable. Ensure that Secrets from service instances and bindings are not deleted before all CAP application resources that depend on them are fully removed.

### CAPApplication is stuck with reason "WaitingForSecrets"

A `CAPApplication` resource in `WaitingForSecrets` state indicates that one or more Secrets referenced under `spec.btp.services` are not present in the cluster. CAP Operator itself cannot resolve this condition — the Secrets are owned and created by an external operator (for instance, the [SAP BTP Service Operator](https://github.com/SAP/sap-btp-service-operator)).

To investigate, inspect the custom resources responsible for creating the missing Secrets — typically `ServiceInstance` and `ServiceBinding` resources of the BTP service operator (or whichever operator manages service bindings in your cluster) — and check their status for errors or failed conditions that may explain why the Secret has not been created.

### Tenant operations or other jobs/pods fail with SAP HANA connection errors

If `CAPTenantOperation` jobs or other pods fail with errors indicating connection problems with SAP HANA, the issue is outside the scope of CAP Operator. Check the following on the consumer side:

- **Entitlements**: Ensure the subaccount has the required entitlements for SAP HANA Cloud/schema.
- **Connection configuration**: Verify that the HANA instance is configured to allow inbound connections from the Kubernetes cluster (for example, IP allowlist / allowed connections settings in the HANA Cloud configuration).
- **Cluster-to-subaccount mapping**: SAP HANA Cloud requires the Kubernetes cluster to be explicitly mapped to the environment context where the HANA instance runs. This mapping must be done per cluster and can optionally be scoped to a specific namespace. See the [SAP HANA Cloud Administration Guide — Map SAP HANA Database to Another Environment Context](https://help.sap.com/docs/hana-cloud/sap-hana-cloud-administration-guide/map-sap-hana-database-to-another-environment-context?ai=true) for instructions.

### Controller memory limits on clusters with a large number of Secrets

CAP Operator relies on a global informer cache that watches Secrets across the entire cluster. It does not currently support namespace-scoped caching or excluding namespaces to limit the set of Secrets held in memory. On clusters with a large number of Secrets, the controller pod may consume significant memory.

If the controller pod is being OOM-killed or is showing high memory usage, increase the memory limit of the CAP Operator controller workload in your Helm values to accommodate the full set of cluster Secrets cached at runtime.
