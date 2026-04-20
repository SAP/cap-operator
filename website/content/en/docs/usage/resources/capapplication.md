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
  providerSubaccountId: 7a49218f-c750-4e1f-a248-7f1cefa13010
  provider: # <-- provider tenant details
    subDomain: cap-app-provider
    tenantId: 7a49218f-c750-4e1f-a248-7f1cefa13010
```

The `btp.services` array specifies all SAP BTP service instances and their corresponding Kubernetes Secrets (containing credentials) required by the application. These service instances are assumed to exist in the provider subaccount. You can use operators such as [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) or [sap-btp-service-operator](https://github.com/SAP/sap-btp-service-operator) to declaratively create these service instances and their credentials as Kubernetes resources.

The `provider` section specifies the provider subaccount linked to this application. The `providerSubaccountId` identifies the the provider subaccount. The combination of `providerSubaccountId` and `btpAppName` (equivalent to `XSAPPNAME`) must be unique, as it is used in various SAP BTP service and application constructs.

The `domainRefs` section references one or more `Domain` or `ClusterDomain` resources.

> NOTE: While the same secondary domain can technically be shared across applications using `ClusterDomain`, tenant subdomains must be unique across all applications sharing that domain.

> NOTE: The `provider` section is omitted for [services-only applications](../../service-exposure/#deploying-services-only-applications).

{{% alert color="warning" title="Warning" %}}
The `globalSubaccountId` field in the `CAPApplication` spec is deprecated and will be removed in a future release. Use `providerSubaccountId` instead.
{{% /alert %}}
