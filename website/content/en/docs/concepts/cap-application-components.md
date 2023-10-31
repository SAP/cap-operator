---
title: "CAP Application Components"
linkTitle: "CAP Application Components"
weight: 20
type: "docs"
description: >
  A typical multi-tenant SAP Cloud Application Programming Model application
---

A full-stack application built with the SAP Cloud Application Programming Model has the following components:

### SAP BTP Service Instances

Multi-tenant CAP-based applications consume services from SAP BTP such as [SAP Authorization and Trust Management Service](https://help.sap.com/docs/authorization-and-trust-management-service?locale=en-US), SAP Software-as-a-Service Provisioning service, and so on. You need to create these service instances within an SAP BTP provider account as well as service keys (bindings) for these instances, which generate the credentials used by the application for accessing these services.

### CAP Application Server

The application provides data models that will be deployed to the connected database. An HTTP server exposes defined services and handles server-side application logic. For more details, check out [the documentation of SAP Cloud Application Programming Model](https://cap.cloud.sap/docs). It's also possible to split the application into multiple servers (services) that work together.

### CAP Components to Support Multitenancy

CAP provides the module `@sap/cds-mtxs`, which can be operated as a sidecar (component running independently from the application server). This component is responsible for handling requests related to tenant management such as onboarding, which then creates the required schema in the connected database. This module also supports triggering tenant management tasks as CLI commands.

### Approuter

The [Approuter](https://www.npmjs.com/package/@sap/approuter), or an extended version of it, takes care of authenticating requests (using the [SAP Authorization and Trust Management Service](https://help.sap.com/docs/authorization-and-trust-management-service?locale=en-US)) and routes the requests to the application servers or related services (for example, 
SAP HTML5 Application Repository service for SAP BTP).

### SAP Fiori Applications

Multiple SAP Fiori front-end applications can connect to the CAP application back end. These UI5 applications are deployed to the SAP HTML5 Application Repository service for SAP BTP and served from there. Similarly, the application can have content specific to other services that need to be deployed, such as the SAP Cloud Portal service.
