---
title: "SubscriptionProvider"
linkTitle: "SubscriptionProvider"
weight: 25
type: "docs"
description: >
  Caches subscription credentials and dependency information for a CAP application
---

{{% alert color="warning" title="Warning" %}}
`SubscriptionProvider` resources are fully managed by CAP Operator. They are automatically created and kept in sync by the controller whenever a `CAPApplication` is reconciled. Do not create, modify, or delete them manually.
{{% /alert %}}

A `SubscriptionProvider` is created by the controller in the same namespace as its owning `CAPApplication`, with the same name. It stores pre-computed subscription credentials and dependency information derived from the `CAPApplication` spec. The [subscription server](../../../concepts/operator-components/subscription-server) uses it to:

- Authorize incoming subscription requests (using the referenced BTP service secrets)
- Return the pre-computed dependency list from the `getDependencies` endpoint of the SaaS Provisioning service

Because all subscription-related lookups happen at `CAPApplication` reconciliation time rather than at HTTP request time, the subscription server can serve requests efficiently without directly parsing the `CAPApplication` spec.

```yaml
apiVersion: sme.sap.com/v1alpha2
kind: SubscriptionProvider
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  appName: cap-app-01
  providerSubaccountId: aa2bae55d7b5-1279-456564-a7b0-aa2bae55d7b5
  subscriptionInfo:
    type: saas-registry
    subscriptionSecret: my-saas-registry-secret
    authSecret: my-xsuaa-secret
  dependencies: '[{"xsappname":"my-destination-service!b42"},{"xsappname":"my-auditlog-service!b7"}]'
```

## Spec

| Field | Description |
|---|---|
| `appName` | Name of the CAP application. Derived from `CAPApplication.spec.btpAppName`. |
| `providerSubaccountId` | Provider subaccount ID. Derived from `CAPApplication.spec.providerSubaccountId`. |
| `subscriptionInfo.type` | Type of subscription service: `saas-registry` or `subscription-manager`, depending on which BTP service is configured in the `CAPApplication`. |
| `subscriptionInfo.subscriptionSecret` | Name of the Kubernetes Secret containing the BTP subscription service credentials (used for request authorization). |
| `subscriptionInfo.authSecret` | (Optional) Name of the Kubernetes Secret containing the XSUAA credentials. Only set for `saas-registry` type. |
| `dependencies` | Pre-computed JSON array of subscription dependencies (for example, `[{"xsappname":"..."}]`). Computed from BTP service secrets at `CAPApplication` reconciliation time and returned verbatim by the subscription server's `getDependencies` endpoint. See [Service Qualification](../../tenant-provisioning#service-qualification) for how dependencies are determined. |
