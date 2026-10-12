---
title: "Subscription"
linkTitle: "Subscription"
weight: 26
type: "docs"
description: >
  Represents an active consumer subscription to a CAP application
---

{{% alert color="warning" title="Warning" %}}
`Subscription` resources are fully managed by CAP Operator. They are created and deleted exclusively by the subscription server in response to callbacks from the SAP Software-as-a-Service Provisioning service or SMS. Do not create, modify, or delete them manually.
{{% /alert %}}

A `Subscription` represents an active subscription of a consumer subaccount to a CAP application. When a consumer subscribes via the SAP BTP cockpit or the SaaS Provisioning service API, the [subscription server](../../../concepts/operator-components/subscription-server) creates a `Subscription` resource in the namespace of the corresponding `CAPApplication`. The controller then creates a [`CAPTenant`](../captenant) as a child of the `Subscription` and drives it through the provisioning flow.

```yaml
apiVersion: sme.sap.com/v1alpha2
kind: Subscription
metadata:
  name: cap-app-01-consumer-sgz8b
  namespace: cap-app-01
spec:
  appName: cap-app-01
  providerSubaccountId: aa2bae55d7b5-1279-456564-a7b0-aa2bae55d7b5
  tenantId: bb3cbf66e8c6-2380-567675-b8c1-bb3cbf66e8c6
  subdomain: consumer-subdomain
  subscriptionGuid: cc4dcg77f9d7-3491-678786-c9d2-cc4dcg77f9d7
  subscriptionDomain: app.example.com
  subscriptionRequestPayload: '{"subscriptionParams":{}}'
status:
  state: Ready
  url: https://consumer-subdomain.app.example.com
```

## Spec

| Field | Description |
|---|---|
| `appName` | Name of the CAP application being subscribed to. Used together with `providerSubaccountId` to identify the owning `CAPApplication`. |
| `providerSubaccountId` | Provider subaccount ID. Used together with `appName` to identify the owning `CAPApplication`. |
| `tenantId` | Tenant ID of the consumer subaccount. |
| `subdomain` | Subdomain of the consumer subaccount. |
| `subscriptionGuid` | Unique GUID of the subscription, as assigned by the SaaS Provisioning service. |
| `subscriptionDomain` | Domain used to construct the tenant-specific subscription URL. If not provided, falls back to the annotation `sme.sap.com/subscription-domain` on the `CAPApplication`, or the first `DomainRef` in the `CAPApplication` spec. |
| `subscriptionRequestPayload` | Full JSON payload of the subscription request. Injected into tenant operation jobs as the `CAPOP_SUBSCRIPTION_PAYLOAD` environment variable. |

## Status

The subscription server polls `Subscription.status` after creating the resource and sends an asynchronous callback to the SaaS Provisioning service once the subscription reaches a terminal state (`Ready` or `Error`).

| Field | Description |
|---|---|
| `state` | Current state of the subscription. See [States](#states) below. |
| `url` | Tenant-specific application URL, populated by the controller once the owned `CAPTenant` is `Ready`. Returned to the SaaS Provisioning service as the subscription URL. |

### States

| State | Description |
|---|---|
| `Processing` | The controller is creating the `CAPTenant` and waiting for provisioning to complete. |
| `ProcessingError` | A retryable error occurred during processing; the controller will retry. |
| `Error` | A terminal error occurred (for example, the owned `CAPTenant` reached `ProvisioningError`). The SaaS Provisioning service is notified of the failure via the async callback. |
| `Deleting` | Deletion has been triggered; the controller is waiting for the owned `CAPTenant` to complete deprovisioning. |
| `Ready` | Provisioning is complete. The `url` field contains the tenant-specific application URL. |
