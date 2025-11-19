---
title: "CAPApplicationVersion"
linkTitle: "CAPApplicationVersion"
weight: 20
type: "docs"
description: >
  How to configure the `CAPApplicationVersion` resource
---

The `CAPApplicationVersion` has the following high level structure:

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

- An instance of `CAPApplicationVersion` is always related to an instance of `CAPApplication` in the same namespace. This reference is established using the attribute `capApplicationInstance`.
- An array of workloads (`workloads`) must be defined that include the various software components of the SAP Cloud Application Programming Model application. A deployment representing the CAP application server or a job that which is used for tenant operations are examples of such workloads. A workload must have either a `deploymentDefinition` or a `jobDefinition`. See the next section for more details.
- An optional attribute `tenantOperations` can be used to define a sequence of steps (jobs) to be executed during tenant operations (provisioning / upgrade / deprovisioning).

> The `CAPApplicationVersion` resource is meant to be immutable - it's spec should not be modified once it is deployed. This is also prevented by our web-hooks which we recommend to always keep active (default).

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

The `type` of the deployment is important to indicate how the operator handles this workload (for example, injection of `destinations` to be used by the approuter). Valid values are:

- `CAP` to indicate a CAP application server. Only one workload of this type can be used at present.
- `Router` to indicate a version of [AppRouter](https://www.npmjs.com/package/@sap/approuter). Only one workload of this type can be used.
- `Additional` to indicate supporting components that can be deployed along with the CAP application server.
- `Service` to indicate workloads that are tenant agnostic.

You can define optional attributes such as `replicas`, `env`, `resources`, `probes`, `securityContext`, `initContainers` and `ports` to configure the deployment.

#### Port configuration

It's possible to define which (and how many) ports exposed by a deployment container are exposed inside the cluster (via services of type `ClusterIP`). The port definition includes a `name` in addition to the `port` number being exposed.

For `deploymentDefinition`, other than type `Router` it would be possible to specify a `routerDestinationName` which would be used as a named `destination` injected into the approuter.

The port configurations aren't mandatory and can be omitted. This would mean that the operator will configure services using defaults. The following defaults are applied if port configuration is omitted:

- For workload of type `CAP`, the default port used by CAP, `4004`, will be added to the service and a destination with name `srv-api` will be added to the approuter referring to this service port (any existing `destinations` environment configuration for this workload will be taken over by overwriting the `URL`).
- For workload of type `Router`, the port `5000` will be exposed in the service. This service will be used as the target for HTTP traffic reaching the application domain (domains are specified within the `CAPApplication` resource).

> NOTE: If multiple ports are configured for a workload of type `Router`, the first available port will be used to target external traffic to the application domain.

#### Monitoring configuration

For each _workload of type deployment_ in a `CAPApplicationVersion`, it is possible to define:
1. Deletion rules: A criteria based on metrics which when satisfied signifies that the workload can be removed
2. Scrape configuration: Configuration which defines how metrics are scraped from the workload service.

Details of how to configure workload monitoring can be found [here](../version-monitoring.md#configure-capapplicationversion).

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

Workloads with a `jobDefinition` represent a job execution at a particular point in the lifecycle of the application or tenant. The following values are allowed for `type` in such workloads:

- `Content`: A content deployer job that can be used to deploy (SAP BTP) service specific content from the application version. This job is executed as soon as a new `CAPApplicationVersion` resource is created in the cluster. Multiple workloads of this type may be defined in the `CAPApplicationVersion` and the order in which they are executed can be specified via `ContentJobs`.
- `TenantOperation`: A job executed during provisioning, upgrade, or deprovisioning of a tenant (`CAPTenant`). These jobs are controlled by the operator and use the `cds/mtxs` APIs to perform HDI content deployment by default. If a workload of type `TenantOperation` isn't provided as part of the `CAPApplicationVersion`, the workload with `deploymentDefinition` of type `CAP` will be used to determine the `jobDefinition` (`image`, `env`, etc.). Also, if `cds/mtxs` APIs are used, `command` can be used by applications to trigger tenant operations with custom command.
- `CustomTenantOperation`: An optional job which runs before or after the `TenantOperation` where the application can perform tenant-specific tasks (for example, create test data).

### Sequencing tenant operations

A tenant operation refers to `provisioning`, `upgrade` or `deprovisioning` which are executed in the context of a CAP application for individual tenants (i.e. using the `cds/mtxs` or similar modules provided by CAP). Within the `workloads`, we have already defined two types of jobs that are valid for such operations, namely `TenantOperation` and `CustomTenantOperation`.

The `TenantOperation` is mandatory for all tenant operations.

In addition, you can choose which `CustomTenantOperation` jobs run for a specific operation and in which order. For example, a `CustomTenantOperation` deploying test data to the tenant database schema would need to run during `provisioning`, but must not run during `deprovisioning`.

The field `tenantOperations` specifies which jobs are executed during the different tenant operations and the order they are executed in.

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

In the example above, for each tenant operation, not only are the valid jobs (steps) specified, but also the order in which they are to be executed. Each step in an operation is defined with:

- `workloadName`refers to the job workload executed in this operation step
- `continueOnFailure` is valid only for `CustomTenantOperation` steps and indicates whether the overall tenant operation can proceed when this operation step fails.

> NOTE:
>
> - Specifying `tenantOperations` is required only if `CustomTenantOperations` are to be used. If not specified, each operation will comprise of only the `TenantOperation` step (the first one available from `workloads`).
> - The `tenantOperations` and specified sequencing are valid only for tenants provisioned (or deprovisioned) on the corresponding `CAPApplicationVersion` and for tenants being upgraded to this `CAPApplicationVersion`.

### Sequencing content jobs

When you create a `CAPApplicationVersion` workload, you can define multiple content jobs. The order in which these jobs are executed is important, as some jobs may depend on the output of others. The `ContentJobs` property allows you to specify the order in which content jobs are executed.

```yaml
spec:
  workloads: # ...
  tenantOperations: # ...
  contentJobs:
    - content-deployer-service
    - content-deployer-ui
```

### ServiceExposures Configuration

See [Service Exposure](../service-exposure/#configuration) page for details.

_Other attributes can be configured as documented._

#### Port configuration

It's possible to define which (and how many) ports exposed by a deployment container are exposed inside the cluster (via services of type `ClusterIP`). The port definition includes a `name` in addition to the `port` number being exposed.

For service only workloads the `routerDestinationName` is not relevant.

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
> The CAP Operator [workloads](../../../reference/#sme.sap.com/v1alpha1.WorkloadDetails) supports several configurations (present in the [kubernetes API](https://kubernetes.io/docs/reference/using-api/)), which can be configured by looking into our API reference:
> - [Container API reference](../../../reference/#sme.sap.com/v1alpha1.ContainerDetails) for generic container-specific configuration
> - [Deployment API reference](../../../reference/#sme.sap.com/v1alpha1.DeploymentDetails) for deployment-specific configuration
> - [Job API reference](../../../reference/#sme.sap.com/v1alpha1.JobDetails) for job-specific configuration
>
> The supported configurations is kept minimal intentionally to keep the overall API simple by considering commonly used configurations.

> Note: For `initContainers` nearly the same environment variables as the main container are made available including VCAP_SERVICES environment.
