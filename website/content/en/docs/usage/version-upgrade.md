---
title: "Application Upgrade"
linkTitle: "Application Upgrade"
weight: 40
type: "docs"
description: >
  How to upgrade to a new Application Version
---

An important lifecycle aspect of operating multi-tenant CAP applications is the tenant upgrade process. With CAP Operator, tenant upgrades can be fully automated by providing a new `CAPApplicationVersion` custom resource.

As covered in [initial deployment](../deploying-application), the `CAPApplicationVersion` resource describes the workloads of an application version, including the container image and services consumed by each component. To upgrade the application, create a new `CAPApplicationVersion` with the updated `image` for each component and a higher semantic version in the `version` field. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplicationVersion).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-2
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-cap-app-01 # <-- reference to CAPApplication in the same namespace
  version: "2.0.1" # <-- semantic version
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend
      consumedBTPServices:
        - app-uaa
        - app-service-manager
        - app-saas-registry
      deploymentDefinition:
        type: CAP # <-- indicates the CAP application server
        image: app.some.repo.example.com/srv/server:0.0.2
        env:
          - name: CDS_ENV
            value: production
          - name: CDS_CONFIG
            value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
    - name: app-router
      consumedBTPServices:
        - app-uaa
        - app-destination
        - app-saas-registry
        - app-html5-repo-runtime
        - app-portal
      deploymentDefinition:
        type: Router
        image: app.some.repo.example.com/approuter/approuter:0.0.2
        env:
          - name: PORT
            value: 4000
          - name: TENANT_HOST_PATTERN
            value: "^(.*).(my.cluster.shoot.url.k8s.example.com|my.example.com)"
    - name: service-content
      consumedBTPServices:
        - app-uaa
        - app-html5-repo-host
        - app-portal
      jobDefinition:
        type: Content
        image: app.some.repo.example.com/approuter/content:0.0.2
        backoffLimit: 1
    - name: tenant-operation
      consumedBTPServices:
        - app-uaa
        - app-service-manager
        - app-saas-registry
      jobDefinition:
        type: TenantOperation
        image: app.some.repo.example.com/approuter/content:0.0.2
        env:
          - name: CDS_ENV
            value: production
          - name: CDS_CONFIG
            value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
    - name: notify-upgrade
      consumedBTPServices: []
      jobDefinition:
        type: CustomTenantOperation
        image: app.some.repo.example.com/approuter/content:0.0.2
        command: ["npm", "run", "notify:upgrade"]
        backoffLimit: 1
        env:
          - name: TARGET_DL
            value: group_xyz@sap.com
  tenantOperations:
    upgrade:
      - workloadName: tenant-operation
      - workloadName: notify-upgrade
        continueOnFailure: true
```

Note that compared to version "1" used for [initial deployment](../deploying-application), new workloads of type `TenantOperation` and `CustomTenantOperation` have been added.

The CAP Operator controller reacts to the new `CAPApplicationVersion` resource by triggering a new deployment for the application server and router, and running the content deployment job. Once the new `CAPApplicationVersion` is `Ready`, **the controller automatically upgrades all relevant tenants** by updating the `version` attribute on the `CAPTenant` resources.

`CAPTenant` reconciliation changes the tenant state to `Upgrading` and creates a `CAPTenantOperation` resource of type upgrade.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenantOperation
metadata:
  name: cap-app-01-provider-fgdfg
  namespace: cap-app-01
spec:
  capApplicationVersionInstance: cav-cap-app-01-2
  subDomain: cap-provider
  tenantId: aa2bae55d7b5-1279-456564-a7b0-aa2bae55d7b5
  operation: upgrade # possible values are provisioning / upgrade / deprovisioning
  steps:
    - name: "tenant-operation"
      type: TenantOperation
    - name: "notify-upgrade"
      type: CustomTenantOperation
      continueOnFailure: true # <-- indicates that the overall operation may proceed even if this step fails
```

The `CAPTenantOperation` creates jobs for each step and executes them sequentially until all jobs complete or one fails. The `CAPTenant` is notified of the result and updates its state accordingly.

When the `CAPTenantOperation` completes successfully, the `VirtualService` managed by the `CAPTenant` is updated to route HTTP traffic to the deployments of the newer `CAPApplicationVersion`. Once all tenants are upgraded, the outdated `CAPApplicationVersion` can be deleted.

## Version Affinity during Upgrade (Experimental)

You can optionally enable Version Affinity for multi-tenant applications by adding the annotation `sme.sap.com/enable-version-affinity: "true"` to the `CAPApplication` resource. With this experimental feature, users remain on the previous `CAPApplicationVersion` during an upgrade until their session expires or they log out.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: test-ca-01
  namespace: default
  annotations:
    sme.sap.com/enable-version-affinity: "true" # <-- enable version affinity
spec:
  btp:
    services:
      - class: xsuaa
        name: cap-uaa
        secret: cap-cap-01-uaa-bind-cf
    ....
  ....
```

By default, CAP Operator recognizes `logout` and `logoff` as logout endpoints. If your application uses a different endpoint, specify it using the `sme.sap.com/logout-endpoint` annotation on your `CAPApplicationVersion` resource (without a leading slash).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-2
  namespace: cap-app-01
  annotations:
    sme.sap.com/logout-endpoint: "custom-logout" # <-- specify custom logout endpoint
spec:
  capApplicationInstance: cap-cap-app-01
  version: "2.0.1"
  registrySecrets:
    - regcred
```
