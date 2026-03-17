---
title: "Deploying a CAP Application"
linkTitle: "Deploying a CAP Application"
weight: 20
type: "docs"
description: >
  How to deploy a new CAP-based application
---

Deploying a multi-tenant CAP application involves defining several key resources provided by the CAP Operator. These resources manage the application's runtime components and external traffic routing.

## Key Resources

1. **CAPApplication** (`capapplications.sme.sap.com`): A namespaced resource that represents the application.

2. **CAPApplicationVersion** (`capapplicationversions.sme.sap.com`): A namespaced resource that specifies the version of the application being deployed. It ensures that all runtime components (deployments, services, and jobs) are created with the specified image version in the same namespace.

3. **Domain resources**: These resources determine how external traffic reaches the application and how DNS and TLS settings are applied. You can choose between:
   - **Domain** (`domains.sme.sap.com`): A namespaced resource for a single application.
   - **ClusterDomain** (`clusterdomains.sme.sap.com`): A cluster-scoped resource that can be shared across multiple applications.

## Deployment Process

Create the `CAPApplication` and `CAPApplicationVersion` resources in the same namespace. This allows CAP Operator to manage all associated runtime components. For external traffic management, define either a `Domain` or `ClusterDomain` resource.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain
metadata:
  namespace: cap-app-01
  name: cap-app-01-primary
spec:
  domain: my.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple
  dnsMode: Wildcard
```

The `ClusterDomain` resource is cluster-scoped and suited for global or shared domain configurations — for example, when multiple applications share the same external domain. See [API Reference](../../reference/#sme.sap.com/v1alpha1.ClusterDomain).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: ClusterDomain
metadata:
  name: common-external-domain
spec:
  domain: my.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple
  dnsMode: Subdomain
```

The `CAPApplication` resource describes the high-level attributes of an application: the SAP BTP account where it is hosted, the consumed SAP BTP services, and references to `Domain` and `ClusterDomain` resources. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplication).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  btpAppName: cap-app-01 # <-- short name (equivalent to SAP BTP XSAPPNAME)
  btp:
    services:
      - class: xsuaa # <-- SAP BTP service technical name
        name: app-uaa # <-- name of the service instance
        secret: cap-app-01-uaa-bind-cf # <-- secret containing credentials for accessing the service (must exist in the same namespace)
      - class: saas-registry
        name: app-saas-registry
        secret: cap-app-01-saas-bind-cf
      - class: service-manager
        name: app-service-manager
        secret: cap-app-01-svc-man-bind-cf
      - class: destination
        name: app-destination
        secret: cap-app-01-dest-bind-cf
      - class: html5-apps-repo
        name: app-html5-repo-host
        secret: cap-app-01-html5-repo-bind-cf
      - class: html5-apps-repo
        name: app-html5-repo-runtime
        secret: cap-app-01-html5-rt-bind-cf
      - class: portal
        name: app-portal
        secret: cap-app-01-portal-bind-cf
  domainRefs:
  - kind: Domain
    name: cap-app-01-primary # <-- reference to Domain resource in the same namespace
  - kind: ClusterDomain
    name: common-external-domain # <-- reference to ClusterDomain resource in the cluster
  globalAccountId: global-account-id
  provider:
    subDomain: cap-app-01-provider
    tenantId: e55d7b5-279-48be-a7b0-aa2bae55d7b5
```

The `CAPApplicationVersion` describes the components of an application version, including the container images to use and the services consumed by each component. It must be created in the same namespace as the `CAPApplication` and must reference it. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplicationVersion).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-1
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-app-01 # <-- reference to CAPApplication in the same namespace
  version: "1" # <-- semantic version
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend
      consumedBTPServices: # <-- services used by the application server (defined in CAPApplication). Credential secrets are mounted as volumes on component pods.
        - app-uaa
        - app-service-manager
        - app-saas-registry
      deploymentDefinition:
        type: CAP # <-- indicates the CAP application server
        image: app.some.repo.example.com/srv/server:0.0.1
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
        image: app.some.repo.example.com/approuter/approuter:0.0.1
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
        image: app.some.repo.example.com/approuter/content:0.0.1
        backoffLimit: 1
```

> NOTE: The example above shows a minimal `CAPApplicationVersion`. For a complete configuration with explanations, see [here](../resources/capapplicationversion).

The CAP Operator controller reacts to these objects and creates additional resources that constitute a running application:

- Deployment (and service) for the application server, with SAP BTP service credentials injected as the `VCAP_SERVICES` environment variable
- Deployment (and service) for the approuter, with destination mappings to the application server and subscription server (for tenant provisioning)
- Job for the version content deployer
- TLS certificates for the specified domains using either ["Gardener" cert-management](https://github.com/gardener/cert-management) or [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- Istio gateway resource for the application domains

> The content deployer deploys content or configuration to SAP BTP services before they are used.

Once these resources are available, the `CAPApplicationVersion` status changes to `Ready`. **The controller then automatically creates a `CAPTenant` object for the provider subaccount tenant.** See [tenant subscription](../tenant-provisioning) for details on how the `CAPTenant` resource is reconciled.

> The `CAPApplicationVersion` resource is immutable — its spec must not be modified after deployment. This is enforced by webhooks, which we recommend keeping active (the default).

> NOTE: Follow the recommended [security measures](../security) to safeguard exposed workloads.
