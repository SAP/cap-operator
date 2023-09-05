---
title: "CAP Operator Overview"
linkTitle: "CAP Operator Overview"
weight: 10
type: "docs"
description: >
  An overview of the architecture
---

The CAP Operator is comprised of the following components

1. **CAP Controller**: a native Kubernetes controller that reconciles custom resources which are defined as part of the operator
2. **Web-hooks**: validating web-hooks to ensure consistency of custom resource objects submitted to kubernetes API server
3. **Subscription Server**: web server for handling HTTP requests submitted by the BTP `saas-registry` service instances during tenant subscription (and unsubscribe)
4. **MTX Job** _[DEPRECATED]_: wrapper component which enables execution of tenant lifecycle operations using `cds/mtx` module provided by CAP, as kubernetes Jobs. _This module is no longer required for applications using the newer `@sap/cds-mtxs` module._

> Note: [`@sap/cds-mtx` is no longer supported with CDS 7](https://cap.cloud.sap/docs/releases/jun23#migration-from-old-mtx). The MTX Job component will be removed once support for older CDS version ends.

The following diagram depicts how the main components interact when deployed to a cluster.

![cluster-components](/cap-operator/img/block-cluster.png)

The following pages provide further details about the CAP Operator components.
