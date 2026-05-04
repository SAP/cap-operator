---
title: "Documentation"
linkTitle: "Documentation"
weight: 10
menu:
  main:
    weight: 10
    pre: "<i class='fas fa-book pr-2'></i>"
---

[**CAP Operator**](https://github.com/sap/cap-operator) deploys and manages the lifecycle of multi-tenant [SAP Cloud Application Programming Model](https://cap.cloud.sap/docs) (CAP) applications and related components within a Kubernetes cluster.

The main features of CAP Operator include:

- Quick and easy deployment of CAP application back ends, routers, and related networking components.
- Integration with SAP Software-as-a-Service Provisioning service to handle asynchronous tenant subscription requests, executing provisioning and deprovisioning tasks as Kubernetes jobs.
- Automated upgrades of known tenants as soon as new application versions are available.
- Deployment of service-specific content and configuration as a Kubernetes job with every application version (for example, HTML5 application content to SAP HTML5 Application Repository service).
- Management of TLS certificates and DNS entries related to the deployed application, with support for customer-specific domains.

The following diagram shows the major automation steps handled by CAP Operator during application deployment:

![workflow](/cap-operator/img/workflow.png)

Explore the following sections to learn more.
