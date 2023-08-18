---
title: "Documentation"
linkTitle: "Documentation"
weight: 20
menu:
  main:
    weight: 10
    pre: "<i class='fas fa-book pr-2'></i>"
---

The [**CAP Operator**](https://github.com/sap/cap-operator) deploys and manages the lifecycle of multi-tenant BTP Golden Path based [CAP](https://cap.cloud.sap/docs) applications and related components, within a Kubernetes cluster.

Main features of the CAP Operator:

- Quick and easy deployment of CAP application backends, router and related networking components.
- Integrates with BTP SaaS Provisioning to handle asynchronous tenant subscription requests, executing provisioning / deprovisioning tasks as Kubernetes jobs.
- Automatically upgrades known tenants when newer application versions are available.
- Supports deployment of service specific content / configuration as a Kubernetes job with with every application version (e.g. HTML5 application content to HTML5 Repository Service).
- Manages TLS certificates and DNS entries related to the deployed application, with support for customer specific domains.

The following picture provides an overview of the major automation steps handled by the Operator during application deployment.

![workflow](/img/workflow.png)

Explore the following chapters to learn more.
