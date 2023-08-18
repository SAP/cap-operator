---
title: "CAP Application Components"
linkTitle: "CAP Application Components"
weight: 20
type: "docs"
description: >
  A typical multi-tenant CAP application
---

A full stack application built using the CAP programming model will have the following components

### SAP BTP Service Instances

Multi-tenant CAP based applications need to consume services from SAP BTP like XSUAA, SaaS Provisioning etc. These service instances need to be created within a BTP Provider Account. Service keys (bindings) need to be created for these instances which generate the credentials used by the application for accessing these services.

### CAP application server

The application provides data models which will be deployed to the connected database. An HTTP server exposes defined services and handles server side application logic. For more details check out [CAP documentation](https://cap.cloud.sap/docs). It is also possible that the application is split into multiple servers (services) which work together.

### CAP components to support Multi-tenancy

CAP provides the module `@sap/cds-mtxs` which can be operated as a sidecar (component running independently from the application server). This component is then responsible for handling requests related to tenant management like onboarding which then creates the required schema in the connected database. This module also supports triggering tenant management tasks as CLI commands.

### AppRouter

The [AppRouter](https://www.npmjs.com/package/@sap/approuter), or an extended version of it, takes care of authenticating requests (using the XSUAA service) and routes the requests to the application servers or related services (e.g. HTML5 Application Repository Service).

### SAP Fiori applications

Multiple SAP Fiori frontend applications may connect to the CAP application backend. These UI5 applications are deployed to the HTML5 Application Repository Service and served from there. Similarly, the application may have content specific to other services which need to be deployed, like the Portal Service.
