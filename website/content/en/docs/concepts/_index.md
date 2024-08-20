---
title: "Concepts"
linkTitle: "Concepts"
weight: 10
type: "docs"
description: >
  Motivation and overview of components
---

Provisioning and operating an SAP Cloud Application Programming Model application on a Kubernetes cluster requires the deployment of various components in addition to the CAP application server (see [a list of typical components](./cap-application-components.md)). Some of these components can be created at the time of system provisioning, while others need to be created (or updated) at different points during the lifecycle of the application (DAY 2 operational tasks).

Using Helm charts to manage the deployment of a CAP application can support the initial system provisioning, but further lifecycle operations (such as tenant provisioning) that are initiated from external components (SAP BTP) require manual adjustment of the deployed resources. An example of such an instance would be the creation of `VirtualServices` (part of Istio service mesh) during tenant provisioning to route application (HTTP) requests submitted on the new tenant subdomain to the application server. Another limitation of using helm charts is the lack of control over the order in which resources are created.

You can get more control over the deployment and further automation of lifecycle operations by extending the Kubernetes API with custom resources that describe the components and the configuration of CAP applications, and controllers to reconcile them. Similar to standard controllers of Kubernetes, the custom controllers watch for changes in the custom resource objects and work towards moving the cluster state to the desired state.

[CAP Operator](https://github.com/sap/cap-operator) comprises of custom resource definitions that describe the CAP application components, the controller to reconcile these resources, and other components that support the lifecycle management.
