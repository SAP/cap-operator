---
title: "Security"
linkTitle: "Security Measures"
weight: 80
type: "docs"
tags: ["security", "security measures", "authentication", "authorization"]
description: >
  Securing your application.
---

## Securing Applications

We strongly recommend applications to implement any necessary authentication and authorization mechanisms to safeguard exposed workloads. This includes implicitly exposed [tenant workloads](./tenant-provisioning/#tenant-provisioning) or explictly exposed [service workloads](./service-exposure).

When using [SAP Authorization and Trust Management Service](https://help.sap.com/docs/authorization-and-trust-management-service?locale=en-US) in the app, this may be done as explained in [this guide](https://help.sap.com/docs/btp/sap-business-technology-platform/protecting-your-application).

### Istio

You may also consider using some of [Istio's security features](https://istio.io/latest/docs/reference/config/security/) for instance using specific workload selectors to secure exposed workloads.