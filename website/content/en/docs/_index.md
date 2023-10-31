---
title: "Documentation"
linkTitle: "Documentation"
weight: 20
menu:
  main:
    weight: 10
    pre: "<i class='fas fa-book pr-2'></i>"
---

[**CAP Operator**](https://github.com/sap/cap-operator) deploys and manages the lifecycle of multi-tenant [SAP Cloud Application Programming Model](https://cap.cloud.sap/docs) based applications and related components, within a Kubernetes cluster.

What are the main features of CAP Operator?

- Quick and easy deployment of CAP application back ends, router, and related networking components.
- Integration with SAP Software-as-a-Service Provisioning service to handle asynchronous tenant subscription requests, executing provisioning / deprovisioning tasks as Kubernetes jobs.
- Automated upgrades of known tenants as soon as new application versions are available.
- Support of deployment of service-specific content / configuration as a Kubernetes job with every application version (for example, HTML5 application content to SAP HTML5 Application Repository service).
- Management of TLS certificates and DNS entries related to the deployed application, with support of customer-specific domains.

Here's an overview of the major automation steps handled by CAP Operator during the deployment of the application:

![workflow](/cap-operator/img/workflow.png)

Explore the following chapters to learn more.
