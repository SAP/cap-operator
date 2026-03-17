---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  What to do before you deploy a new CAP application
---

## Prepare the SAP BTP global account and provider subaccount

CAP-based applications use various SAP BTP services created in a provider subaccount. Before deploying the application, create a global account and entitle the required services. Then create a provider subaccount where the service instances can be created. See the [SAP BTP account administration documentation](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration) for details.

## Create service instances and bindings

A multi-tenant CAP-based application consumes the following SAP BTP services. Some parameters require special attention during service instance creation. Service keys (bindings) generate access credentials, which must be provided as Kubernetes Secrets in the namespace where the application is deployed.

Other services (not listed here) may also be used depending on your requirements (for example, SAP HTML5 Application Repository service for SAP BTP, Business Logging, and so on).

> Note: If some SAP BTP services are not available on Kubernetes, enable Cloud Foundry for the provider subaccount. In such cases, use the [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) to manage service instances and bindings directly from within the Kubernetes cluster. It automatically generates secrets containing service access credentials based on the service bindings.

### SAP Authorization and Trust Management Service

The parameter `oauth2-configuration.redirect-uris` must include the domain used by the application. For example, if the application is hosted in a "Gardener" managed cluster, the entry may have the form `https://*<application-specific-prefix>.<cluster-id>.<gardener-project-id>.shoot.url.k8s.example.com/**`.

Scopes required for asynchronous tenant subscription operations must also be included. Additionally, check the [CAP Multitenancy](https://cap.cloud.sap/docs/java/multitenancy#xsuaa-mt-configuration) documentation for additional required scopes.

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
    - description: With this scope set, the callbacks for tenant onboarding, offboarding, and getDependencies can be called
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
When using multiple [SAP Authorization and Trust Management Service](https://help.sap.com/docs/authorization-and-trust-management-service?locale=en-US) instances in the app (for example, one for `application` and another for `apiaccess`), set the primary instance using the annotation `sme.sap.com/primary-xsuaa` with the `name` of the service instance:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  annotations:
    "sme.sap.com/primary-xsuaa": "my-cap-app-uaa" # Tells CAP Operator which UAA instance to use for the application
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

### SAP Software-as-a-Service Provisioning service

When creating an instance of the SaaS Provisioning service, configure asynchronous tenant subscription callbacks. See [Register Your Multi-Tenant Application/Service in SaaS Provisioning](https://help.sap.com/docs/btp/sap-business-technology-platform/register-multitenant-application-to-sap-saas-provisioning-service?locale=en-US&version=LATEST) for more details.

```yaml
parameters:
  appName: <short-application-name>
  appUrls:
    callbackTimeoutMillis: 300000 # <-- fails the subscription process when no response is received within this timeout
    getDependencies: https://<provider-subaccount-subdomain>.<cap-app-name>.cluster-x.my-project.shoot.url.k8s.example.com/callback/v1.0/dependencies # <-- handled by the application
    onSubscription: https://<cap-operator-subscription-server-domain>/provision/tenants/{tenantId} # <-- the /provision route is forwarded directly to CAP Operator (Subscription Server) and must be specified as such
    onSubscriptionAsync: true
    onUnSubscriptionAsync: true
```

### SAP HANA Cloud

An SAP HANA Cloud instance (preferably shared and accessible from the provider subaccount) is required. Note the Instance ID of the database for use in relevant workloads. The SAP HANA Schemas & HDI Containers service must also be entitled for the provider subaccount.

### SAP Service Manager service

The SAP Service Manager service allows CAP to retrieve schema- (tenant-) specific credentials for connecting to the SAP HANA Cloud database.
