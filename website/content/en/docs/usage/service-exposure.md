---
title: "Service Exposure"
linkTitle: "Service Exposure"
weight: 42
type: "docs"
tags: ["service exposure", "services only", "tenant agnostic"]
description: >
  How to expose service workloads (tenant agnostic).
---
# Exposing Service Workloads

This guide explains how to deploy applications with tenant agnostic service workloads. These workloads can be part of multi-tenant applications or standalone applications that are completely tenant agnostic.

## Configuration

### Service Exposure Setup

The `serviceExposures` section in the `CAPApplicationVersion` configuration is crucial for exposing workloads. Each entry in the `serviceExposures` array specifies a subdomain under which workloads are accessible, allowing multiple routes per subdomain.

For some more details on configuring routes, see the [Route API reference](../reference/#sme.sap.com/v1alpha1.Route)

### Example Configuration

```yaml
spec:
  workloads:
    - name: cap-backend-service
      consumedBTPServices:
        - cap-uaa
        - cap-saas-reg
      deploymentDefinition:
        type: CAP # <-- possible values are CAP / Router / Additional / Service
        image: some.repo.example.com/cap-app/server:3.22.11
        env:
          - name: HOME
            value: "SAP"
        replicas: 3
        ports:
          - name: app-port
            port: 4004
          - name: tech-port
            port: 4005
          - name: api
            port: 8000
          - name: api-v2
            port: 8001
            appProtocol: http
    - name: router
      consumedBTPServices:
        - cap-uaa
        - cap-apps-repo
      deploymentDefinition:
        type: Router
        image: some.repo.example.com/cap-app/app-router:1.0.1
        ports:
          - name: router-port
            port: 5000
    - name: app
      consumedBTPServices:
        - cap-uaa
        - cap-db
      deploymentDefinition:
        type: Service
        image: some.repo.example.com/cap-app/app:4.0.1
        ports:
          - name: app-port
            port: 5000
    - name: service-content
      consumedBTPServices:
        - app-uaa
        - app-html5-repo-host
        - app-portal
      jobDefinition:
        type: Content
        image: some.repo.example.com/cap-app/content:0.0.1
        backoffLimit: 1
  serviceExposures:
    - subDomain: service
      routes:
        - workloadName: cap-backend-service
          port: 4004
    - subDomain: api
      routes:
        - workloadName: cap-backend-service
          port: 8001
          path: /api/v2
        - workloadName: cap-backend-service
          port: 8000
          path: /api
    - subDomain: app
      routes:
        - workloadName: app
          port: 5000
```

#### Result:
For a cluster domain like `my.cluster.shoot.url.k8s.example.com`, the configuration will generate URLs like:
- `service.my.cluster.shoot.url.k8s.example.com` for `cap-backend-service` on port `4004`.
- `api.my.cluster.shoot.url.k8s.example.com/api/v2` for `cap-backend-service` on port `8001`.
- `api.my.cluster.shoot.url.k8s.example.com/api` for `cap-backend-service` on port `8000`
- `app.my.cluster.shoot.url.k8s.example.com` for `app` on port `5000`.

In the above example, the `router` workload is not exposed via `servicesExposure`. However, for multi-tenant scenarios it may be exposed per tenant sub-domain as usual.

#### Additional Consideration:
Ensure routes are ordered correctly to prevent routing errors. If there are multiple routes defined for a subdomain, the application needs to maintain the routes in the right order to avoid incorrect routing. For example, in the example configuration above, the `api` subdomain where the more specific path `/api/v2` must be defined before the more general path `/api`.

## Deploying Services Only Applications

Services only applications don't require tenant-specific configurations. Therefore, the `provider` section is omitted from the `CAPApplication` resource, and the `CAPApplicationVersion` may only contain `Content` jobs and no tenant related jobs. The rest of the configuration for your services-only application remains unchanged.

### Application Configuration

Create a `CAPApplication` resource without a `provider` section:

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
    name: common-external-domain
  globalAccountId: btp-glo-acc-id
```

### Version Configuration

Create a `CAPApplicationVersion` in the same namespace as the `CAPApplication` with service workloads and any content jobs.

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
        - app-db
        - app-saas-registry
      deploymentDefinition:
        type: CAP
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
    - name: api
      consumedBTPServices: # Services used by this workload
        - app-uaa
        - app-db
      deploymentDefinition:
        type: Service
        image: app.some.repo.example.com/srv/api:0.0.1
        env:
          - name: CDS_ENV
            value: production
        ports:
          - name: apiv2
            port: 8000
            appProtocol: http
          - name: api
            port: 8001
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
        - workloadName: api
          port: 8000
          path: /api/v2
        - workloadName: api
          port: 8001
          path: /api
```

## Important Considerations

- No tenant-related resources are created for services-only applications.
- A successful upgrade of the `CAPApplicationVersion` will cause any service related `VirtualService` resources to be modified to route HTTP traffic to the deployments that `CAPApplicationVersion`.
- Choose the appropriate application mode (services-only or multi-tenant) from the start, as switching modes later is not possible.
- Follow the recommended [security measures](./security) to safeguard exposed workloads.
