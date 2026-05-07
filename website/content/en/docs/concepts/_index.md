---
title: "Concepts"
linkTitle: "Concepts"
weight: 10
type: "docs"
description: >
  Motivation and overview of components
sidebar_root_for: children
---

Provisioning and operating an SAP Cloud Application Programming Model (CAP) application on a Kubernetes cluster requires deploying various components in addition to the CAP application server (see [a list of typical components](./cap-application-components)). Some of these components can be created during initial system provisioning, while others need to be created or updated at different points in the application lifecycle (Day 2 operations).

Using Helm charts to manage the deployment of a CAP application supports initial system provisioning, but further lifecycle operations (such as tenant provisioning) triggered by external components (SAP BTP) require manual adjustment of the deployed resources. For example, Istio `VirtualService` resources must be created during tenant provisioning to route incoming HTTP requests on the new tenant subdomain to the application server. Another limitation of Helm charts is the lack of control over the order in which resources are created.

You can gain greater control over deployment and automate lifecycle operations by extending the Kubernetes API with custom resources that describe CAP application components and their configuration, along with controllers to reconcile them. Like standard Kubernetes controllers, these custom controllers watch for changes in custom resource objects and work to bring the cluster state to the desired state.

[CAP Operator](https://github.com/sap/cap-operator) comprises custom resource definitions that describe CAP application components, a controller that reconciles these resources, and additional components that support lifecycle management.
