---
title: "CAP Operator Overview"
linkTitle: "CAP Operator Overview"
weight: 10
type: "docs"
description: >
  An overview of the architecture
---

CAP Operator is comprised of the following components:

1. **CAP Controller**: a native Kubernetes controller that reconciles custom resources defined as part of the operator
2. **Webhooks**: validating webhooks to ensure consistency of custom resource objects submitted to the Kubernetes API server
3. **Subscription Server**: web server for handling HTTP requests submitted by the SAP BTP `saas-registry` service instances during tenant subscription (and unsubscribe)

The following diagram depicts how the main components interact when deployed to a cluster:

![cluster-components](/cap-operator/img/block-cluster.drawio.svg)

Looking for more details about the CAP Operator components? Go to the next pages. 
