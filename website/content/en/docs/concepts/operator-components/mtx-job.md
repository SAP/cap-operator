---
title: "MTX Job"
linkTitle: "MTX Job"
weight: 30
type: "docs"
description: >
  Executing `cds-mtx` routes as Kubernetes Jobs
---

CAP provides the [`cds/mtx`](https://cap.cloud.sap/docs/guides/multitenancy/old-mtx-apis) module which provides APIs (HTTP endpoints) for triggering tenant lifecycle operations like provisioning or upgrade. Even though these routes can be served from a deployment of the CAP application server, they consume considerably higher memory compared to application routes. It would be ideal to execute such operations, independent from the application server, as dedicated Kubernetes jobs which can be monitored. As the current `cds-mtx` version operates only as a web-server serving specific lifecycle routes, a trigger or wrapper is required which starts the `cds-mtx` server, executes the required lifecycle route with the given payload, and finally shuts down the server.

MTX Job component was developed as such a wrapper which runs as a sidecar container within the job pod, along with the `cds-mtx` server, and manages the lifecycle operation. During the reconciliation of custom resource `CAPTenantOperation` which represents a tenant lifecycle operation, the controller creates Jobs where MTX Job is added as a sidecar to the `cds-mtx` server. The MTX Job component waits for the `cds-mtx` server to start, triggers the required lifecycle route, and waits for it to be completed. Finally, it shuts down the `cds-mtx` server and completes the job with the appropriate exit code. This is achieved using a `netcat` listener in the job pod template to allow the trigger to manage the mtx container by sending a dummy connect to the mtx pod (listener) and hence exit gracefully.

MTX Job will connect to [XSUAA service](https://help.sap.com/viewer/5088c3bb02144e7782959bb1529ca70e/SHIP/en-US/9cde62c2d3a8440caae18f7dbcf68d4c.html) for a valid authentication token to trigger the required lifecycle operation.

> Note: [`@sap/cds-mtx` is no longer supported with CDS 7](https://cap.cloud.sap/docs/releases/jun23#migration-from-old-mtx). This MTX Job component will be removed once support for older CDS version ends.
