---
title: "Controller"
linkTitle: "Controller"
weight: 10
type: "docs"
description: >
  Reconciliation of custom resource objects
---

The CAP controller uses [client-go](https://github.com/kubernetes/client-go) from Kubernetes, which provides the tools and utilities needed to interact with the Kubernetes API server and manage the custom resources defined by CAP Operator.

The controller uses `Informers` to watch certain resources and invokes registered event handlers when these resources are modified. To streamline the processing of such notifications, rate-limiting queues are implemented that store changes and allow processing of items in independent reconciliation threads (goroutines). This design enables sequential processing of changed items and avoids conflicts.

The following _namespaced_ custom resources are reconciled by the CAP controller:

- `CAPApplication`: Defines a high-level application, its domains, and the consumed SAP BTP services.
- `CAPApplicationVersion`: A child resource of `CAPApplication` that contains container images used to deploy application components (workloads) of a specific version.
- `CAPTenant`: A child resource of `CAPApplication` that corresponds to an SAP BTP subaccount subscribed to the application.
- `CAPTenantOperation`: Represents a provisioning, deprovisioning, or upgrade operation on a tenant, scheduled as a child resource of a `CAPTenant` and executed as a sequence of specified steps.

> Parent-child relationships between custom resources are established by defining owner references for the children.

![controller](/cap-operator/img/block-controller.drawio.svg)
