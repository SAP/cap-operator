---
title: "Troubleshooting"
linkTitle: "Troubleshooting"
weight: 90
type: "docs"
description: >
  Common issues and how to solve them
---

### Usage of @sap/cds-mtxs library for multitenancy

> The CAP Operator utilizes the `@sap/cds-mtxs` library. Prior to version 0.7.0 one could disable this by setting the IS_MTXS_ENABLED environment variable to "false" in the TenantOperation workload, in which case the old `@sap/cds-mtx` library-based wrapper job was used instead. However, this is no longer supported and is removed as support for older CDS version (v6) has ended.

CAP Operator supports the usage of `@sap/cds-mtxs` (which replaces the former `@sap/cds-mtx` library) from the SAP Cloud Application Programming Model by default.

This enables us to use built-in (into `@sap/cds-mtxs`) CLI-based handling for tenant operations during provisioning, deprovisioning, and upgrading tenants.

As of now, for the usage of this new library, you (depending on your k8s cluster hardening setup) need to add additional `securityContext` for the `TenantOperation` and also `CAP` workloads as shown in the sample below.

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

### Secret/credential handling for different workloads of the CAP Operator

Libraries like `xsenv`/`cds`(CAP) handle credentials differently in different environments (CF, K8s) and on K8s when using credential data directly from secrets, any JSON data type information related to the data values may get lost and lead to inconsistencies.

This issue is now addressed by the SAP Service Binding Specification, which mandates the addition of metadata to these secrets. Both `btp-service-operator` and `cf-service-operator` supports the addition of metadata. But, in case this feature is not used in your clusters, CAP Operator avoids inconsistencies by creating `VCAP_SERVICES` environment variable across all workloads and expects all SAP BTP services credentials to be available in Kubernetes Secrets under a key `credentials`.

This can be achieved using the `secretKey` property for a `ServiceBinding` created using `btp-service-operator` or `cf-service-operator`, for example:

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

> We recommend that you use `secretKey`, even when credential metadata is available to reduce the overhead of interpreting parsing multiple JSON attributes.

### HTTP requests reaching the AppRouter are not getting forwarded to the application server (pods)

The Approuter component maps incoming requests to destinations (applications or services) that have been configured. If you're using an `xs-app.json` file with your Approuter to specify route mapping to various destinations, ensure that the `destinationName` property for the
SAP Cloud Application Programming Model back end is specified in the corresponding CAPApplicationVersion configuration. CAP Operator will inject this destination to the Approuter pods (via environment variables).


### HTTP Requests Timing Out in the Approuter for Long-Running Operations in Back End Workload

If your back-end service is known to take a long time, configure the `destinations` environment variable on the Approuter component to set the desired timeout configuration for that destination (`destinationName`). CAP Operator will overwrite the URL part of that destination to point to the right workload, the remaining settings are taken over exactly as configured.

### Supported Approuter Version

Use `@sap/approuter` version `14.x.x` (or higher).

### CAP Operator Resources Can't Be Deleted in the K8S Cluster/Namespace

All custom resource objects (CROs) created by CAP Operator are protected with `finalizers` to ensure a proper cleanup takes place.
For instance, when deleting a `CAPApplication` CRO, any existing tenants would be deprovisioned automatically to avoid inconsistenties. Once the deprovisioning is successful, the corresponding CROs would be removed automatically.
The provider `CAPTenant` resource can't be deleted before deleting a consistent `CAPApplication`.
_NOTE_: CAP operator needs the `secrets` from service instances/bindings to exist for the entire lifecycle of the
SAP Cloud Application Programming Model application. Removing the service instances/bindings i.e. the secrets from the cluster while the CAP application related CROs still exist would cause leftover resources in cluster (and perhaps the db). Recovering from such inconsistent states might not even be possible.
Such a situation can easily arise when using `helm` delete/uninstall as the order of deletion of resouces is not configurable. We recommend that you do this with care.
It's important that you ensure that the secrets from service instance/bindings aren't deleted before any
SAP Cloud Application Programming Model application that consumes those secrets is completely removed.
