---
title: "CAPApplication"
linkTitle: "CAPApplication"
weight: 10
type: "docs"
description: >
  How to configure the `CAPApplication` resource
---

Here's an example of a fully configured `CAPApplication`:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app
  namespace: cap-ns
spec:
  btp:
    services:
      - class: xsuaa
        name: cap-uaa
        secret: cap-uaa-bind
      - class: saas-registry
        name: cap-saas-reg
        secret: cap-saas-reg-bind
      - class: service-manager
        name: cap-service-manager
        secret: cap-svc-man-bind
      - class: destination
        name: cap-destination
        secret: cap-bem-02-dest-bind
      - class: html5-apps-repo
        name: cap-html5-repo-host
        secret: cap-html5-repo-bind
      - class: html5-apps-repo
        name: cap-html5-repo-runtime
        secret: cap-html5-rt-bind
      - class: portal
        name: cap-portal
        secret: cap-portal-bind
      - class: business-logging
        name: cap-business-logging
        secret: cap-business-logging-bind
  btpAppName: cap-app
  domainRefs:
  - kind: Domain
    name: cap-app-01-primary
  - kind: ClusterDomain
    name: common-external-domain
  globalAccountId: 2dddd48d-b45f-45a5-b861-a80872a0c8a8
  provider: # <-- provider tenant details
    subDomain: cap-app-provider
    tenantId: 7a49218f-c750-4e1f-a248-7f1cefa13010
```

The overall list of SAP BTP service instances and respective Secrets (credentials) required by the application is specified as an array in `btp.services`. These service instances are assumed to exist in the provider subaccount. Operators such as [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) or [sap-btp-service-operator](https://github.com/SAP/sap-btp-service-operator) can be used to declaratively create these service instances and their credentials as Kubernetes resources.

The `provider` section specifies details of the provider subaccount linked to this application, while `globalAccountId` denotes the global account in which the provider subaccount is created. Within a global account, the `btpAppName` has to be unique as this is equivalent to `XSAPPNAME`, which is used in various SAP BTP service and application constructs.

The `domainRefs` section specifies references one or more `Domain` or `ClusterDomain` resources.
> NOTE: While the same secondary domain can technically be used across applications using `ClusterDomain`; the consumers need to ensure that the tenant sub-domains are unique across such applications that share the same domain!

> NOTE: The `provider` section is omitted for [Services Only Applications](../services-workload.md)
