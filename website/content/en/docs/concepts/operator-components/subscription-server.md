---
title: "Subscription Server"
linkTitle: "Subscription Server"
weight: 20
type: "docs"
description: >
  Integration with SAP Software-as-a-Service Provisioning service (SaaS)
---

The Subscription Server handles HTTP requests from the [SAP Software-as-a-Service Provisioning service](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/5e8a2b74e4f2442b8257c850ed912f48.html) for tenant subscription operations on SAP Cloud Application Programming Model applications installed in the cluster.

During the creation of a `saas-registry` service instance (in the provider subaccount), [callback URLs are configured](../../../usage/prerequisites/#sap-software-as-a-service-provisioning-service) to point to the subscription server routes. Additionally, the `getDependencies` URLs can also be configured to point to the subscription server routes.

When a consumer tenant subscribes to an application managed by the operator, the subscription server receives the callback, validates the request using credentials from the corresponding [`SubscriptionProvider`](../../../usage/resources/subscriptionprovider) resource, and creates a [`Subscription`](../../../usage/resources/subscription) resource in the namespace of the identified `CAPApplication`. The controller then creates the `CAPTenant` and drives it through the provisioning flow.

The subscription server returns an `Accepted` (202) response and starts a background routine that polls `Subscription.status` while the `Subscription` and `CAPTenant` resources are independently reconciled by the controller.

Once the tenant provisioning process completes (or fails), the tracking routine returns the appropriate status to the SaaS Registry via an asynchronous callback.


![subscription](/cap-operator/img/block-subscription.drawio.svg)


([More details about asynchronous tenant subscription](https://help.sap.com/docs/btp/sap-business-technology-platform/register-multitenant-application-to-sap-saas-provisioning-service?version=Cloud&q=async))

This asynchronous approach avoids timeouts during synchronous calls and enables the scheduling of dedicated jobs (via `CAPTenantOperation`) for completing the subscription and performing any additional cluster tasks (for example, creating an Istio `VirtualService` for the tenant subdomain).

## Subscription Limit

The subscription server enforces an optional upper bound on the number of active subscriptions per application, configured via `CAPApplication.spec.maxSubscriptions`. Provisioning requests that would exceed the limit are rejected with HTTP 422.

Limit enforcement is serialized within a single subscription server pod. Running the subscription server as a **single replica** (the default) is therefore recommended when strict enforcement is required. With multiple replicas, concurrent requests across pods can briefly exceed the limit. See [SubscriptionProvider — Subscription Limit](../../../usage/resources/subscriptionprovider#subscription-limit) for details.
