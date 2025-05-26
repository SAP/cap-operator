---
title: "Services Only Applications"
linkTitle: "Services Only Applications"
weight: 50
type: "docs"
tags: ["services Only", "tenant independent"]
description: >
  Deploying CAP applications with only service workloads (tenant-independent).
---

This guide explains how to deploy a CAP application containing only service workloads (those that are tenant-independent).

## Deploying Services Only Applications

Services only applications don't require tenant-specific configurations. Therefore, the `provider` section is omitted from the `CAPApplication` resource, and the `CAPApplicationVersion` should only define deployments of type `Service`, alongside optional `Content` jobs.

Because these applications are tenant-independent, no tenant related resources are created.

The service workloads may be exposed externally via `serviceExposures` configuration on the [version](#version-configuration-capapplicationversion).

### Application Configuration (`CAPApplication`)

Create a `CAPApplication` resource without a `provider` section, as shown below:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: test-ca-01
  namespace: default
spec:
  btp:
    services:
      - class: xsuaa
        name: cap-uaa
        secret: cap-cap-01-uaa-bind-cf
      - class: xsuaa
        name: cap-uaa2
        secret: cap-cap-01-uaa2-bind-cf
      - class: service-manager
        name: cap-service-manager
        secret: cap-cap-01-svc-man-bind-cf
  btpAppName: test-cap-01
  domainRefs:
  - kind: Domain
    name: cap-app-01-primary
  - kind: ClusterDomain
    name: common-secondary-domain
  globalAccountId: btp-glo-acc-id
```

### Version Configuration (`CAPApplicationVersion`)

Create a `CAPApplicationVersion` in the same namespace as the `CAPApplication` with service workloads and any content jobs. The `serviceExposures` section defines how the service is exposed externally, for example, via Istio `VirtualService` resources.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-ca-app-01-1
  namespace: default # Same namespace as CAPApplication
spec:
  capApplicationInstance: test-ca-01 # Reference to the CAPApplication
  version: "0.0.1"
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend-service
      consumedBTPServices: # Services used by this workload
        - app-uaa
        - app-service-manager
        - app-saas-registry
      deploymentDefinition:
        type: Service # Defines this as a service workload
        image: app.some.repo.example.com/srv/server:0.0.1
        env:
          - name: CDS_ENV
            value: production
        ports:
          - name: server
            port: 4004
            appProtocol: http
          - name: api
            port: 8000
            appProtocol: http
          - name: metrics
            port: 4005
            appProtocol: http
    - name: service-content # Example content job
      consumedBTPServices:
        - app-uaa
        - app-html5-repo-host
        - app-portal
      jobDefinition:
        type: Content
        image: app.some.repo.example.com/approuter/content:0.0.1
        backoffLimit: 1
  serviceExposures:
    - subDomain: service
      routes:
        - workloadName: cap-backend-service
          port: 4004
    - subDomain: api
      routes:
        - workloadName: cap-backend-service
          port: 8000
          path: /api
```

### Important Considerations

* The `CAPApplication` reaches a `Consistent` state, only after
  - the latest `CAPApplicationVersion` is Ready.
  - the creation of Istio `VirtualService`, which allows HTTP requests on the `serviceExposure` subdomain to reach the application.
* The `CAPApplication` status for services only applications will have a `servicesOnly` field set to `true`.
* There is no `CAPTenant` or other tenant related resources created for such services only scenario. Any tenant-related logic within the service itself is the responsibility of the consuming application.
* You cannot switch a `CAPApplicationVersion` between services only and tenant-dependent modes after initial creation of overall application. Choose the appropriate mode from the start.
* A successful upgrade of the `CAPApplicationVersion` will cause any service related `VirtualService` resources to be modified to route HTTP traffic to the deployments of the newer `CAPApplicationVersion`. Once a new `CAPApplicationVersion` is `Ready` and the service only application is automatically upgraded, the outdated `CAPApplicationVersion` can be deleted.
