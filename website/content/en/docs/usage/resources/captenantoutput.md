---
title: "CAPTenantOutput"
linkTitle: "CAPTenantOutput"
weight: 50
type: "docs"
description: >
  How to configure the `CAPTenantOutput` resource
---

[`CAPTenantOutput`](../../../reference/#sme.sap.com/v1alpha1.CAPTenantOutput) can be used to add additional data to the asynchronous callback parameters sent by the SaaS provisioning service during tenant onboarding. The resource is not reconciled; it is consumed by the subscription server to generate additional callback data. It has the following structure:

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
The example above shows a resource associated with a tenant via the `sme.sap.com/btp-tenant-id` label, which must be set by consumers.

{{% alert color="warning" title="Warning" %}}
This resource is intended to be created or updated during tenant operations, such as those triggered during tenant onboarding. Its primary purpose is to enhance the parameters of the subscription callback during tenant onboarding, though it may be used for additional scenarios in the future.

Any RBAC changes required to create or modify this resource (for example, in a custom tenant operation) must be handled by consumers and assigned to the relevant job via the `serviceAccountName` configuration for that workload.

All instances of this resource for a given tenant are cleaned up before any `CAPTenantOperation` is created.
{{% /alert %}}
