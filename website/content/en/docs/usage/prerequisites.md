---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  What to do before deploying a new CAP Application
---

### Prepare BTP Global Account and Provider Subaccount

CAP based applications make use of various BTP services which are created in a Provider Subaccount. So, before the application can be deployed, it is required to create a Global Account and assign the required services which will be used. You can do this using [SAP BTP Control Center](https://controlcenter.ondemand.com/index.html). Once this is done, a Provider Subaccount needs to be created, where the required service instances can be created.

### Create Service Instances and Bindings

A multi-tenant CAP based application will need to consume the following BTP services. While creating these service instances, some of the parameters supplied require special attention. Service Keys (Bindings) are then created to generate access credentials, which in turn should be provided as Kubernetes Secrets in the namespace where the application is being deployed.

Other services (not listed here) may also be used depending on the requirement (e.g. HTML5 Repository Service, Business Logging etc.).

> IMPORTANT: Due to limited availability of BTP services on Kubernetes, certain services will need to be created by enabling Cloud Foundry for the provider subaccount. We recommend to use the [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) for managing the Service Instances and Service Bindings directly from within the Kubernetes cluster. Based on the Service Bindings, it automatically generates the secrets containing the service access credentials.

##### XSUAA Service

The parameter `oauth2-configuration.redirect-uris` must include the domain used by the application. As an example based on the cluster setup this url may have the form `https://*<application-specific-prefix>.<cluster-id>.<gardener-project-id>.shoot.url.k8s.example.com/**`.

Scope required to make asynchronous tenant subscription operations need to be included. Additionally, check the [CAP Multi-tenancy](https://cap.cloud.sap/docs/java/multitenancy#xsuaa-mt-configuration) documentation for additional scopes which are required.

```yaml
parameters:
  authorities:
    - $XSAPPNAME.mtcallback
    - $XSAPPNAME.mtdeployment
  oauth2-configuration:
    redirect-uris:
      - https://*my-cap-app.cluster-x.my-project.shoot.url.k8s.example.com/**
  role-collections:
    ...
  role-templates:
    ...
  scopes:
    - description: UAA
      name: uaa.user
    - description: With this scope set, the callbacks for tenant onboarding, offboarding and getDependencies can be called
      grant-as-authority-to-apps:
        - $XSAPPNAME(application,sap-provisioning,tenant-onboarding)
      name: $XSAPPNAME.Callback
    - description: Async callback to update the saas-registry (provisioning succeeded/failed)
      name: $XSAPPNAME.subscription.write
    - description: Deploy applications
      name: $XSAPPNAME.mtdeployment
    - description: Subscribe to applications
      grant-as-authority-to-apps:
        - $XSAPPNAME(application,sap-provisioning,tenant-onboarding)
      name: $XSAPPNAME.mtcallback
    ...
```
When using mulitple xsuaa service instances in the app (e.g. one for the `application` and other `apiaccess`). The primary xsuaa instance can be set using the annotation: "sme.sap.com/primary-xsuaa" with the value being the `name` of the service instance, as shown below:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  annotations:
    "sme.sap.com/primary-xsuaa": "my-cap-app-uaa" # This let's the CAP Operator determine/use the right UAA instance for the application.
  name: test-cap-01
  ...
spec:
  btp:
    services:
      - class: xsuaa
        name: my-cap-app-uaa-api
        secret: my-cap-app-uaa-api-bind-cf
      - class: xsuaa
        name: my-cap-app-uaa
        secret: my-cap-app-uaa-bind-cf
      - class: saas-registry
        name: my-cap-app-saas-registry
        secret: my-cap-app-saas-bind-cf
      ...
  btpAppName: my-cap-app
  ...
```

##### SaaS Provisioning Service

When creating an instance of the SaaS Provisioning Service, it should be configured to use asynchronous tenant subscription callbacks. See [here](https://controlcenter.ondemand.com/index.html#/knowledge_center/articles/f239e5501a534b64ab5f8dde9bd83c53) for more details.

```yaml
parameters:
  appName: <short-application-name>
  appUrls:
    callbackTimeoutMillis: 300000 # <-- used to fail subscription process when no response is received
    getDependencies: https://<provider-subaccount-subdomain>.<cap-app-name>.cluster-x.my-project.shoot.url.k8s.example.com/callback/v1.0/dependencies # <-- handled by the application
    onSubscription: https://<cap-operator-subscription-server-domain>/provision/tenants/{tenantId} # <-- the /provision route is forwarded directly to the CAP Operator (Subscription Server) and should be specified as such
    onSubscriptionAsync: true
    onUnSubscriptionAsync: true
```

##### SAP HANA Cloud

A SAP HANA Cloud instance (preferably shared and accessible from the provider subaccount) is required. The Instance ID of the database must be noted for usage in relevant workloads. SAP HANA Schemas & HDI Containers service should also be entitled for the provider subaccount.

##### Service Manager

The Service Manager Service allows CAP to retrieve schema (tenant) specific credentials to connect to the HANA database.
