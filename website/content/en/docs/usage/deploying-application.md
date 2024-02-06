---
title: "Deploying a CAP Application"
linkTitle: "Deploying a CAP Application"
weight: 20
type: "docs"
description: >
  How to deploy a new CAP-based application
---

Just by defining two resources provided by CAP Operator, namely `capapplications.sme.sap.com` and `capapplicationversions.sme.sap.com`, it's possible to deploy a multi-tenant CAP application and start using it. These resources are _namespaced_ and so the CAP Operator will create all related resources (deployments, gateways, jobs etc.) within the same namespace.

The object, `CAPApplication`, describes the high-level attributes of an application such as the SAP BTP account where it is hosted, the consumed SAP BTP services, domains where the application routes will be made available etc. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplication).

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  btpAppName: cap-app-01 # <-- short name (similar to SAP BTP XSAPPNAME)
  btp:
    services:
      - class: xsuaa # <-- SAP BTP service technical name
        name: app-uaa # <-- name of the service instance
        secret: cap-app-01-uaa-bind-cf # <-- secret containing the credentials to access the service existing in the same namespace
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
  domains:
    istioIngressGatewayLabels: # <-- labels used to identify the Istio ingress gateway (the values provided here are the default values)
      - name: app
        value: istio-ingressgateway
      - name: istio
        value: ingressgateway
    primary: "cap-app-01.cluster.shoot.url.k8s.example.com" # <-- primary domain where the application is exposed. Each tenant will have access to a subdomain of this domain. Ensure that this is at most 62 chars long.
    secondary:
      - "alt.shoot.example.com"
  globalAccountId: global-account-id
  provider:
    subDomain: cap-app-01-provider
    tenantId: e55d7b5-279-48be-a7b0-aa2bae55d7b5
```

The object, `CAPApplicationVersion`, describes the different components of an application version including the container images to be used and the services consumed by each component. See [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplicationVersion).

The `CAPApplicationVersion` must be created in the same namespace as the `CAPApplication` and refers to it.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-1
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-cap-app-01 # <-- reference to CAPApplication in the same namespace
  version: "1" # <-- semantic version
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend
      consumedBTPServices: # <-- these are services used by the application server (already defines as part of CAPApplication resource). Corresponding credential secrets will be mounted onto the component pods as volumes.
        - app-uaa
        - app-service-manager
        - app-saas-registry
      deploymentDefinition:
        type: CAP # <-- indicates the CAP application server
        image: app.some.repo.example.com/srv/server:0.0.1
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
        image: app.some.repo.example.com/approuter/approuter:0.0.1
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
        image: app.some.repo.example.com/approuter/content:0.0.1
        backoffLimit: 1
```

> NOTE: The example above is a minimal `CAPApplicationVersion` that can be deployed. For a more supported configuration and their explanations, see [here](../resources/capapplicationversion).

The controller component of CAP Operator reacts to these objects and creates further resources, which constitute a running application:

- Deployment (and service) for the application server with credentials (from secrets) to access SAP BTP services injected as `VCAP_SERVICES` environment variable
- Deployment (and service) for the approuter with destination mapping to the application server and subscription server (for the tenant provisioning route)
- Job for the version content deployer
- TLS certificates for the domains provided using either [Gardener cert-management](https://github.com/gardener/cert-management) or [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- Istio gateway resource for the application domains

> The content deployer is used to deploy content or configuration to SAP BTP services, before using them.

Once these resources are available, the `CAPApplicationVersion` status changes to `Ready`. **The controller proceeds to automatically create an object of type `CAPTenant`, which corresponds to the tenant of the provider subaccount.** Please see [tenant subscription]({{< ref "/tenant-provisioning.md" >}}) for details on how the `CAPTenant` resource is reconciled.

> The `CAPApplicationVersion` resource is meant to be immutable - it's spec should not be modified once it is deployed. This is also prevented by our web-hooks which we recommend to always keep active (default).
