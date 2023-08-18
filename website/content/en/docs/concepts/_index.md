---
title: "Concepts"
linkTitle: "Concepts"
weight: 10
type: "docs"
description: >
  Motivation and overview of components
---

Provisioning and operating a CAP Application on a Kubernetes cluster requires deployment of various components in addition to the CAP application server (see [a list of typical components]({{< ref "/cap-application-components.md" >}})). Some of these components can be created at the time of system provisioning, while others need to be created (or updated) at different points during the lifecycle of the application (DAY 2 operational tasks).

Using helm charts to manage a CAP Application deployment can support the initial system provisioning, but further lifecycle operations like tenant provisioning, which are initiated from external components (SAP BTP), will require manual adjustment of the deployed resources. An example of such an instance would be the creation of `VirtualServices` (part of Istio service mesh) during tenant provisioning to route application (HTTP) requests submitted on the new tenant subdomain to the application server. Another limitation of using helm charts is the lack of control over the order in which resources are created.

More control over the deployment and further automation of lifecycle operations can be achieved by extending the Kubernetes API with custom resources, which describe the components and configuration of CAP applications, and controllers to reconcile them. Similar to standard controllers of Kubernetes the custom controllers watch for changes in the custom resource objects and work towards moving the cluster state to the desired state.

The [CAP Operator](https://github.com/sap/cap-operator) comprises of Custom Resource Definitions which describe the CAP application components, the controller to reconcile these resources, and other components which support the lifecycle management.
