---
title: "CAPApplicationVersion"
linkTitle: "CAPApplicationVersion"
weight: 20
type: "docs"
description: >
  How to configure the `CAPApplicationVersion` resource
---

The `CAPApplicationVersion` has the following high-level structure:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-v1
  namespace: cap-ns
spec:
  version: 3.2.1 # <-- semantic version (must be unique within the versions of a CAP application)
  capApplicationInstance: cap-app
  registrySecrets: # <-- image pull secrets to be used in the workloads
    - regcred
  workloads: # <-- define deployments and jobs used for this application version
    - name: "cap-backend"
      deploymentDefinition: # ...
      consumedBTPServices: # ...
    - name: "app-router"
      deploymentDefinition: # ...
      consumedBTPServices: # ...
    - name: "service-content"
      jobDefinition: # ...
      consumedBTPServices: # ...
    - name: "tenant-operation"
      jobDefinition: # ...
      consumedBTPServices: # ...
  tenantOperations: # ... <-- (optional)
```

- A `CAPApplicationVersion` is always associated with a `CAPApplication` in the same namespace, referenced via the `capApplicationInstance` attribute.
- The `workloads` array defines the software components of the application. Examples include a deployment for the CAP application server or a job for tenant operations. Each workload must have either a `deploymentDefinition` or a `jobDefinition`. See the next section for details.
- The optional `tenantOperations` attribute defines a sequence of steps (jobs) to execute during tenant operations (provisioning, upgrade, or deprovisioning).

> The `CAPApplicationVersion` resource is immutable — its spec must not be modified after deployment. This is enforced by webhooks, which we recommend keeping active (the default).

### Workloads with `deploymentDefinition`

```yaml
name: cap-backend
consumedBTPServices: # <-- an array of service instance names referencing the SAP BTP services defined in the CAPApplication resource
  - cap-uaa
  - cap-saas-reg
deploymentDefinition:
  type: CAP # <-- possible values are CAP / Router / Additional / Service
  image: some.repo.example.com/cap-app/server:3.22.11 # <-- container image
  env: # <-- (optional) same as in core v1 pod.spec.containers.env
    - name: SAY
      value: "I'm GROOT"
  replicas: 3 # <-- (optional) replicas for scaling
  ports:
    - name: app-port
      port: 4004
      routerDestinationName: cap-server-url
    - name: tech-port
      port: 4005
  monitoring:
    scrapeConfig:
      port: tech--port
    deletionRules:
      expression: scalar(sum(avg_over_time(current_sessions{job="cav-cap-app-v1-cap-backend-svc",namespace="cap-ns"}[2h]))) <= bool 5
```

The `type` of the deployment indicates how the operator handles this workload (for example, injection of `destinations` used by the Approuter). Valid values are:

- `CAP` to indicate a CAP application server. Only one workload of this type is allowed.
- `Router` to indicate a version of the [Approuter](https://www.npmjs.com/package/@sap/approuter). Only one workload of this type is allowed.
- `Additional` to indicate supporting components deployed alongside the CAP application server.
- `Service` to indicate workloads that are tenant-agnostic.

You can define optional attributes such as `replicas`, `env`, `resources`, `probes`, `securityContext`, `initContainers`, and `ports` to configure the deployment.

#### Port configuration

You can define which ports (and how many) exposed by a deployment container are made available inside the cluster (via Services of type `ClusterIP`). The port definition includes a `name` in addition to the `port` number being exposed.

For `deploymentDefinition` types other than `Router`, you can specify a `routerDestinationName` that is used as a named `destination` injected into the Approuter.

The port configurations are not mandatory and can be omitted. When omitted, the operator applies the following defaults:

- For workloads of type `CAP`, the default port `4004` is added to the Service, and a destination named `srv-api` is added to the Approuter referencing this service port (any existing `destinations` environment configuration for this workload is preserved, with only the `URL` overwritten).
- For workloads of type `Router`, port `5000` is exposed in the Service. This Service is used as the target for HTTP traffic reaching the application domain (domains are specified in the `CAPApplication` resource).

> NOTE: If multiple ports are configured for a workload of type `Router`, the first port is used to target external traffic to the application domain.

#### Monitoring configuration

For each _deployment workload_ in a `CAPApplicationVersion`, you can define:
1. Deletion rules: Criteria based on metrics that, when satisfied, indicate the workload can be removed.
2. Scrape configuration: Defines how metrics are scraped from the workload service.

Details of how to configure workload monitoring can be found [here](../../version-monitoring#configure-capapplicationversion).

### Workloads with `jobDefinition`

```yaml
workloads:
  # ... deployment workloads have been omitted in this example
  - name: "content-deployer"
    consumedServices: # ...
    jobDefinition:
      type: Content
      image: some.repo.example.com/cap-app/content:1.0.1
  - name: "tenant-operation"
    consumedServices: # ...
    jobDefinition:
      type: TenantOperation
      image: some.repo.example.com/cap-app/server:3.22.11
      backoffLimit: 2 # <-- determines retry attempts for the job on failure (default is 6)
      ttlSecondsAfterFinished: 300 # <-- the job will be cleaned up after this duration
      env:
        - name: CDS_ENV
          value: production
        - name: CDS_CONFIG
          value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
  - name: "notify-upgrade"
    consumedServices: # ...
    jobDefinition:
      type: CustomTenantOperation
      image: # ...
      command: ["npm", "run", "notify:upgrade"] # <-- custom entry point for the container allows reuse of a container image with multiple entry points
      backoffLimit: 1
  - name: "create-test-data"
    consumedServices: # ...
    jobDefinition:
      type: CustomTenantOperation
      image: # ...
      command: ["npm", "run ", "deploy:testdata"]
```

Workloads with a `jobDefinition` represent a job that executes at a particular point in the lifecycle of the application or tenant. The following values are allowed for `type` in such workloads:

- `Content`: A content deployer job that deploys SAP BTP service-specific content from the application version. This job runs as soon as a new `CAPApplicationVersion` resource is created in the cluster. Multiple workloads of this type may be defined, and the order in which they run can be specified via `ContentJobs`.
- `TenantOperation`: A job executed during provisioning, upgrade, or deprovisioning of a tenant (`CAPTenant`). These jobs are controlled by the operator and use the `cds/mtxs` APIs to perform HDI content deployment by default. **A workload of type `TenantOperation` must always be defined in the `CAPApplicationVersion` for multi-tenant applications.** If `cds/mtxs` APIs are used, `command` can be specified to trigger tenant operations with a custom command.
- `CustomTenantOperation`: An optional job that runs before or after the `TenantOperation`, allowing the application to perform tenant-specific tasks (for example, creating test data).

### Sequencing tenant operations

A tenant operation refers to `provisioning`, `upgrade`, or `deprovisioning`, which are executed in the context of a CAP application for individual tenants (using the `cds/mtxs` or similar modules provided by CAP). Within the `workloads`, two types of jobs are valid for such operations: `TenantOperation` and `CustomTenantOperation`.

The `TenantOperation` is mandatory for all tenant operations.

In addition, you can choose which `CustomTenantOperation` jobs run for a specific operation and in which order. For example, a `CustomTenantOperation` that deploys test data to the tenant database schema should run during `provisioning` but must not run during `deprovisioning`.

The field `tenantOperations` specifies which jobs run during the different tenant operations and their execution order.

```yaml
spec:
  workloads: # ...
  tenantOperations:
    provisioning:
      - workloadName: "tenant-operation"
      - workloadName: "create-test-data"
    upgrade:
      - workloadName: "notify-upgrade"
        continueOnFailure: true # <-- indicates the overall operation may proceed even if this step fails
      - workloadName: "tenant-operation"
      - workloadName: "create-test-data"
    # <-- as the deprovisioning steps are not specified, only the `TenantOperation` workload (first available) will be executed
```

In the example above, for each tenant operation, the valid jobs (steps) and their execution order are specified. Each step in an operation is defined with:

- `workloadName` refers to the job workload executed in this operation step.
- `continueOnFailure` is valid only for `CustomTenantOperation` steps and indicates whether the overall tenant operation can proceed when this step fails.

> NOTE:
>
> - `tenantOperations` is only required if `CustomTenantOperation`s are used. If not specified, each operation consists only of the `TenantOperation` step (the first one found in `workloads`).
> - A workload of type `TenantOperation` must always be present in the `CAPApplicationVersion`. The previous behaviour of falling back to the `CAP` deployment workload when no `TenantOperation` job was defined is no longer supported.
> - The `tenantOperations` sequencing applies only to tenants provisioned (or deprovisioned) on this `CAPApplicationVersion` and to tenants being upgraded to it.

### Sequencing content jobs

When you create a `CAPApplicationVersion`, you can define multiple content jobs. The order in which these jobs run is important, as some jobs may depend on the output of others. The `ContentJobs` property specifies the execution order of content jobs.

```yaml
spec:
  workloads: # ...
  tenantOperations: # ...
  contentJobs:
    - content-deployer-service
    - content-deployer-ui
```

### ServiceExposures Configuration

See [Service Exposure](../../service-exposure/#configuration) page for details.

_Other attributes can be configured as documented._

#### Port configuration

You can define which ports (and how many) exposed by a deployment container are made available inside the cluster (via Services of type `ClusterIP`). The port definition includes a `name` in addition to the `port` number being exposed.

For service-only workloads, the `routerDestinationName` is not relevant.

The port configurations are mandatory and cannot be omitted.

### Full Example

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-v1
  namespace: cap-ns
spec:
  version: 3.2.1
  capApplicationInstance: cap-app
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend
      consumedBTPServices:
        - cap-uaa
        - cap-service-manager
        - cap-saas-reg
      deploymentDefinition:
        type: CAP
        image: some.repo.example.com/cap-app/server:3.22.11
        env:
          - name: CDS_ENV
            value: production
          - name: CDS_CONFIG
            value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
        replicas: 3
        ports:
          - name: app-port
            port: 4004
            routerDestinationName: cap-server-url
          - name: tech-port
            port: 4005
            appProtocol: grpc
        monitoring:
          scrapeConfig:
            port: tech--port
          deletionRules:
            expression: scalar(sum(avg_over_time(current_sessions{job="cav-cap-app-v1-cap-backend-svc",namespace="cap-ns"}[2h]))) <= bool 5
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: 4005
          initialDelaySeconds: 20
          periodSeconds: 10
          timeoutSeconds: 2
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: 4005
          initialDelaySeconds: 20
          periodSeconds: 10
          timeoutSeconds: 2
        resources:
          limits:
            cpu: 200m
            memory: 500Mi
          requests:
            cpu: 20m
            memory: 50Mi
        securityContext:
          runAsUser: 1000
          runAsGroup: 2000
    - name: "app-router"
      consumedBTPServices:
        - cap-uaa
        - cap-saas-reg
        - cap-html5-repo-rt
      deploymentDefinition:
        type: Router
        image: some.repo.example.com/cap-app/router:4.0.1
        env:
          - name: PORT
            value: "3000"
        ports:
          - name: router-port
            port: 3000
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 20
          periodSeconds: 10
          timeoutSeconds: 2
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 20
          periodSeconds: 10
          timeoutSeconds: 2
        resources:
          limits:
            cpu: 200m
            memory: 500Mi
          requests:
            cpu: 20m
            memory: 50Mi
        podSecurityContext:
          runAsUser: 2000
          fsGroup: 2000
    - name: "service-content"
      consumedServices:
        - cap-uaa
        - cap-portal
        - cap-html5-repo-host
      jobDefinition:
        type: Content
        image: some.repo.example.com/cap-app/content:1.0.1
        securityContext:
          runAsUser: 1000
          runAsGroup: 2000
    - name: "ui-content"
      consumedServices:
        - cap-uaa
        - cap-portal
        - cap-html5-repo-host
      jobDefinition:
        type: Content
        image: some.repo.example.com/cap-app/ui-content:1.0.1
        securityContext:
          runAsUser: 1000
          runAsGroup: 2000
    - name: "tenant-operation"
      consumedServices: # ...
      jobDefinition:
        type: TenantOperation
        image: some.repo.example.com/cap-app/server:3.22.11
        backoffLimit: 2
        ttlSecondsAfterFinished: 300
        env:
          - name: CDS_ENV
            value: production
          - name: CDS_CONFIG
            value: '{ "requires":{"cds.xt.DeploymentService":{"hdi": { "create":{ "database_id": "16e25c51-5455-4b17-a4d7-43545345345" } } } } }'
    - name: "notify-upgrade"
      consumedServices: []
      jobDefinition:
        type: CustomTenantOperation
        image: some.repo.example.com/cap-app/server:3.22.11
        command: ["npm", "run", "notify:upgrade"]
        backoffLimit: 1
    - name: "create-test-data"
      consumedServices:
        - cap-service-manager
      jobDefinition:
        type: CustomTenantOperation
        image: some.repo.example.com/cap-app/server:3.22.11
        command: ["npm", "run ", "deploy:testdata"]
  tenantOperations:
    provisioning:
      - workloadName: "tenant-operation"
      - workloadName: "create-test-data"
    upgrade:
      - workloadName: "notify-upgrade"
        continueOnFailure: true
      - workloadName: "tenant-operation"
      - workloadName: "create-test-data"
  contentJobs:
    - service-content
    - ui-content
```
> NOTE:
> The CAP Operator [workloads](../../../reference/#sme.sap.com/v1alpha1.WorkloadDetails) support several configurations (drawn from the [Kubernetes API](https://kubernetes.io/docs/reference/using-api/)), which can be found in the API reference:
> - [Common API reference](../../../reference/#sme.sap.com/v1alpha1.CommonDetails) for generic container configuration
> - [Deployment API reference](../../../reference/#sme.sap.com/v1alpha1.DeploymentDetails) for deployment-specific configuration
> - [Job API reference](../../../reference/#sme.sap.com/v1alpha1.JobDetails) for job-specific configuration
>
> The supported configurations are intentionally kept minimal to keep the overall API simple, covering only the most commonly used options.

> Note: `initContainers` have access to nearly the same environment variables as the main container, including the `VCAP_SERVICES` environment variable.
