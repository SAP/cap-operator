---
title: "Controller"
linkTitle: "Controller"
weight: 10
type: "docs"
description: >
  Reconciliation of Custom Resource Objects
---

The CAP Controller is implemented using the [client-go](https://github.com/kubernetes/client-go) from Kubernetes, which provides the required tools and utilities to interact with the Kubernetes API server. It manages custom resources which are included with the operator.

The controller uses `Informers` to watch certain resources and invokes registered event handlers when these resources are modified. To streamline the processing of such notifications, rate limiting queues are implemented which store the changes and allow processing of these items in independent reconciliation threads (go routines). Such a design allows sequential processing of the changed items and avoids conflicts.

The following _namespaced_ Custom Resources have been defined to be reconciled by the CAP controller:

- `CAPApplication`: defines a high level application, its domains and consumed BTP services
- `CAPApplicationVersion`: defines a child resource of the `CAPApplication` which contains container images which will be used to deploy application components (workloads) of a specific version
- `CAPTenant`: represents a child resource of the `CAPApplication` which corresponds to a BTP sub-account which has subscribed to the application
- `CAPTenantOperation`: represents a provisioning, deprovisioning or upgrade operation on a tenant which is scheduled as a child resource of a `CAPTenant` and executed as a sequence of specified steps.

> Parent-child relationships between custom resources are established by defining owner references for the children.

![controller](/img/block-controller.png)
