---
title: "CAP Operator Overview"
linkTitle: "CAP Operator Overview"
weight: 10
type: "docs"
description: >
  An overview of the architecture
---

CAP Operator consists of the following components:

1. **CAP Controller**: A native Kubernetes controller that reconciles custom resources defined as part of the operator.
2. **Webhooks**: Validating webhooks that ensure consistency of custom resource objects submitted to the Kubernetes API server.
3. **Subscription Server**: A web server that handles HTTP requests submitted by SAP BTP `saas-registry` service instances during tenant subscription and unsubscription.

The following diagram shows how the main components interact when deployed to a cluster:

![cluster-components](/cap-operator/img/block-cluster.drawio.svg)

For more details about each component, see the following pages.
