---
title: "Application Upgrade"
linkTitle: "Application Upgrade"
weight: 40
type: "docs"
description: >
  How to upgrade to a new Application Version
---

An important lifecycle aspect of operating multi-tenant CAP applications is the tenant upgrade process. With CAP Operator, these tenant upgrades can be fully automated by providing a new instance of the `capapplicationversions.sme.sap.com` custom resource.
As you've already seen during the [initial deployment]({{< ref "/deploying-application.md" >}}), the `CAPApplicationVersion` resource describes the different components (workloads) of an application version that includes the container image to be used and the services consumed by each component.
To upgrade the application, provide a new `CAPApplicationVersion` with the relevant `image` for each component and use a newer (higher) semantic version in the `version` field. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplicationVersion).

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
          - name: CDS_MTX_PROVISIONING_CONTAINER
            value: '{"provisioning_parameters": { "database_id": "16e25c51-5455-4b17-a4d7-43545345345"}}'
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
            value: "^(.*).(cap-app-01.cluster.shoot.canary.k8s-hana.ondemand.co|alt.shoot.example.com)"
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
          - name: CDS_MTX_PROVISIONING_CONTAINER
            value: '{"provisioning_parameters": { "database_id": "16e25c51-5455-4b17-a4d7-43545345345"}}'
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

Note that in this version (compared to version "1" used for the [initial deployment]({{< ref "/deploying-application.md" >}})), new workloads of type `TenantOperation` and `CustomTenantOperation` have been added.

The controller component of CAP Operator reacts to the new `CAPApplicationVersion` resource and triggers another deployment for the application server, router and triggers the content deployment job. Once the new `CAPApplicationVersion` is `Ready`, **the controller proceeds to automatically upgrade all relevant tenants** i.e. by updating the `version` attribute on the `CAPTenant` resources.

The reconciliation of a `CAPTenant` changes its state to `Upgrading` and creates the `CAPTenantOperation` resource of type upgrade.

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
      continueOnFailure: true # <-- can be set for workloads of type CustomTenantOperation to indicate that the success of this job is optional for the completion of the overall operation
```

The `CAPTenantOperation` creates jobs for each of the steps involved and executes them sequentially until all the jobs are finished or one of them fails. The `CAPTenant` is notified about the result and updates its state accordingly.

A successful completion of the `CAPTenantOperation` will cause the `VirtualService` managed by the `CAPTenant` to be modified to route HTTP traffic to the deployments of the newer `CAPApplicationVersion`. Once all tenants have been upgraded, the outdated `CAPApplicationVersion` can be deleted.
