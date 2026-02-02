---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  What to do before you deploy a new CAP application
---

## Prepare the SAP BTP global account and provider subaccount

CAP-based applications make use of various SAP BTP services that are created in a provider subaccount. So, before you can deploy the application, create a global account and entitle the required services that will be used. Once done, create a provider subaccount, where the required service instances can be created. To do so, [refer to the documentation here](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration).

## Create service instances and bindings

A multi-tenant CAP-based application consumes the following SAP BTP services. While creating these service instances, some of the parameters supplied require special attention. Service keys (bindings) are then created to generate access credentials, which in turn should be provided as Kubernetes Secrets in the namespace where the application is being deployed.

Other services (not listed here) may also be used depending on the requirement (for example, SAP HTML5 Application Repository service for SAP BTP, Business Logging, and so on).

> Note: If some SAP BTP services are not available on Kubernetes, enable Cloud Foundry for the provider subaccount to create certain services. In such cases you may use the [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) for managing the service instances and service bindings directly from within the Kubernetes cluster. Based on the service bindings, it automatically generates the secrets containing the service access credentials.

### SAP Authorization and Trust Management Service

The parameter `oauth2-configuration.redirect-uris` must include the domain used by the application. For instance, if the application is hosted in a "Gardener"  managed cluster, the entry may have the form `https://*<application-specific-prefix>.<cluster-id>.<gardener-project-id>.shoot.url.k8s.example.com/**`.

Scope required to make asynchronous tenant subscription operations need to be included. Additionally, check the [CAP Multitenancy](https://cap.cloud.sap/docs/java/multitenancy#xsuaa-mt-configuration) documentation for additional scopes which are required.

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
When using mulitple [SAP Authorization and Trust Management Service](https://help.sap.com/docs/authorization-and-trust-management-service?locale=en-US) instances in the app (for example, one for the `application` and other `apiaccess`). The primary instance can be set using the annotation: "sme.sap.com/primary-xsuaa" with the value being the `name` of the service instance, as shown below:

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

### SAP Software-as-a-Service Provisioning service

When creating an instance of the SaaS Provisioning service, use asynchronous tenant subscription callbacks in the configuration. See [Register Your Multi-Tenant Application/Service in SaaS Provisioning](https://help.sap.com/docs/btp/sap-business-technology-platform/register-multitenant-application-to-sap-saas-provisioning-service?locale=en-US&version=LATEST) for more details.

```yaml
parameters:
  appName: <short-application-name>
  appUrls:
    callbackTimeoutMillis: 300000 # <-- used to fail subscription process when no response is received
    getDependencies: https://<provider-subaccount-subdomain>.<cap-app-name>.cluster-x.my-project.shoot.url.k8s.example.com/callback/v1.0/dependencies # <-- handled by the application
    onSubscription: https://<cap-operator-subscription-server-domain>/provision/tenants/{tenantId} # <-- the /provision route is forwarded directly to CAP Operator (Subscription Server) and must be specified as such
    onSubscriptionAsync: true
    onUnSubscriptionAsync: true
```

### SAP HANA Cloud

An SAP HANA Cloud instance (preferably shared and accessible from the provider subaccount) is required. The Instance ID of the database must be noted for usage in relevant workloads. SAP HANA Schemas & HDI Containers service must also be entitled for the provider subaccount.

###  SAP Service Manager service

The SAP Service Manager service allows CAP to retrieve schema-(tenant-)specific credentials to connect to the SAP HANA Cloud database.
