---
title: "Subscription Server"
linkTitle: "Subscription Server"
weight: 20
type: "docs"
description: >
  Integration with SaaS Provisioning Service
---

The Subscription Server handles HTTP requests from the [SaaS Provisioning Service](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/2cd8913a50bc4d3e8172f84bb4bfba20.html) for tenant subscription operations on CAP applications which have been installed in the cluster. 

During the creation of a `saas-registry` service instance (in the provider sub-account) [callback URLs are configured](../../../usage/prerequisites/#saas-provisioning-service) which should point to the subscription server routes.

When a consumer tenant subscribes to an application managed by the operator a subscription callback is received by the subscription server which then generates the `CAPTenant` custom resource object. 

The subscription server returns an `Accepted` (202) response code and starts a routine/thread which keeps polling for the tenant status until the changes to the `CAPTenant` are then independently reconciled by the controller. 

Once the tenant provisioning process has completed (or has failed), the tracking routine will return the appropriate status to the SaaS Registry via an asynchronous callback (by obtaining the necessary authorization token).


![subscription](/img/block-subscription.png)


([More details about asynchronous tenant subscription](https://controlcenter.ondemand.com/index.html#/knowledge_center/articles/2316430f7d804820934910db736cefbf).)

Such an asynchronous processing allows us to avoid timeouts during synchronous calls, as well as schedule dedicated jobs (via `CAPTenantOperation`) for completion of the subscription and perform any further tasks required in the cluster (e.g. create a `VirtualService` corresponding to the tenant subdomain).
