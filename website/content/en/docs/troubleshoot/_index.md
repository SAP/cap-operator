---
title: "Troubleshooting"
linkTitle: "Troubleshooting"
weight: 90
type: "docs"
description: >
  Common issues and how to solve them
---

**Usage of @sap/cds-mtxs library for multitenancy**

> By default, the CAP Operator utilizes the `@sap/cds-mtxs` library. However, you can disable this by setting the IS_MTXS_ENABLED environment variable to "false" in the TenantOperation workload, in which case the old `@sap/cds-mtx` library based wrapper job will be used instead. As mentioned in the CAP documentation, [`@sap/cds-mtx` is no longer supported with CDS 7](https://cap.cloud.sap/docs/releases/jun23#migration-from-old-mtx). The MTX Job component will be removed once support for older CDS version ends.

The CAP Operator supports usage of `@sap/cds-mtxs` (which is the replacement for the former `@sap/cds-mtx` library) from CAP by default.

This enables us to get rid of our [wrapper implementation](../concepts/operator-components/mtx-job/) and instead use built-in (into `@sap/cds-mtxs`) cli based handling for tenant operations during provisioning, deprovisioning and upgrading tenants.

As of now for the usage of this new library you may (depending on your k8s cluster hardening setup) need to add additional `securityContext` for the `TenantOperation` and also `CAP` workloads as shown in the sample below. 

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
      - name: CDS_MTX_PROVISIONING_CONTAINER
        value: '{ "provisioning_parameters": { "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } }'
      image: "some.repo.example.com/cap-app/server"
      securityContext: # needed until CAP resolves issue with folder creation in the root dir of the app container at runtime
        runAsUser: 1000
```

**Secret/credential handling for different workloads of the CAP Operator**

Libraries like `xsenv`/`cds`(CAP) handle credentials differently in different environments (CF, K8s) and on K8s when using credential data directly from secrets, any JSON data type information related to the data values may get lost and lead to inconsistencies.

This issue is now addressed by the SAP Service Binding Specification, which mandates the addition of metadata to these secrets. Both `btp-service-operator` and `cf-service-operator` supports the addition of metadata. But, in case this feature is not used in your clusters, the CAP Operator avoids inconsistencies by creating `VCAP_SERVICES` environment variable across all workloads and expects all BTP services credentials to be available in Kubernetes secrets under a key `credentials`.

This can be achieved using the `secretKey` property for a `ServiceBinding` created using `btp-service-operator` or `cf-service-operator`, e.g.:

```
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

>  It is recommended to use `secretKey`, even when credential metadata is available to reduce the overhead of interpreting parsing multiple JSON attributes.

**HTTP requests reaching the AppRouter are not getting forwarded to the application server (pods)**

The AppRouter component maps incoming requests to destinations (applications or services) which have been configured. If you are using an `xs-app.json` file with your AppRouter to specify route mapping to various destinations, ensure that the `destinationName` property for the CAP backend is specified in the corresponding CAPApplicationVersion configuration. The CAP operator will inject this destination to the AppRouter pods (via environment variables).


**HTTP requests are timing out in the AppRouter for long running operations in backend workload**

If your backend service is known to take a long time, configure the `destinations` environment variable on the AppRouter component to set the desired timeout configuration for that destination (`destinationName`). The CAP Operator will just overwrite the URL part of that destination to point to the right workload, remaining settings are taken over exactly as configured.

**Recommended AppRouter version**

Use `@sap/approuter` version `14.x.x` (or higher).

**CAP Operator resources cannot be deleted in the k8s cluster/namespace**

All custom resource objects (CROs) created by the CAP Operator are protected with `finalizers` to ensure proper cleanup takes place.
For instance, when deleting a `CAPApplication` CRO any existing tenants would be deprovisioned automatically to avoid inconsistenties. Once the deprovisioning is successful the corresponding CROs would be removed automatically.
The provider `CAPTenant` resource cannot be deleted while before deleting a consistent `CAPApplication`.
_NOTE_: The CAP operator needs the `secrets` from service instances/bindings to exist for the entire lifecycle of the cap application. Removing the service instances/bindings i.e. the secrets from the cluster while the CAP application related CROs still exist would cause leftover resources in cluster (and perhaps the db). Recovering from such inconsistent states might not even be possible.
Such a situation can easily arise when using `helm` delete/uninstall as the order of deletion of resouces is not configurable. We recommend you do this with care.
It is important to ensure that the secrets from service instance/bindings are not deleted before any CAP application that consumes those secrets is completely removed.
