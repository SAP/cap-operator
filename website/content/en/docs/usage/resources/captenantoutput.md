---
title: "CAPTenantOutput"
linkTitle: "CAPTenantOutput"
weight: 50
type: "docs"
description: >
  How to configure the `CAPTenantOutput` resource
---

The [`CAPTenantOutput`](docs/reference/#sme.sap.com/v1alpha1.CAPTenantOutput) may be used to add additional data to the asynchronous callback parameters from the SaaS provisioning service during tenant onboarding. The resource is not reconciled but just consumed by the subscription server to generate additional data. It has the following structure:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPTenantOutput
metadata:
  name: cap-app-consumer-output
  namespace: cap-ns
  labels:
    sme.sap.com/btp-tenant-id: cb46733-1279-48be-fdf434-aa2bae55d7b5
spec:
  subscriptionCallbackData: '{foo: bar}'
  
```
The example above shows an instance of the resource that is associated with a tenant via the `sme.sap.com/btp-tenant-id` label (which must be set by consumers).

{{< alert color="warning" title="Warning" >}}
The resource is meant to be created/updated during tenant operations for e.g. the ones created during tenant onboarding. As of now, the primary intention of this resource is to enhance the parameters of subscription callback during tenant onboarding. But the resources may be used for further scenarios in the future.

Any RBAC related updates needed to create/modify the resources for e.g. in a custom tenant operation needs to be handled by consumers and assigned to the relevant job via `serviceAccountName` config for that workload (job).

Note that all instances of this resources found for a given tenant will be cleaned up before any `CAPTenantOperation` is created.
{{< /alert >}}