# Troubleshooting

Common issues with CAP Operator-managed applications and how to resolve them.

## Quick reference

| Symptom | Likely Cause | Action |
|---|---|---|
| `CAPApplicationVersion` stuck in `Processing` | Content job failing | `kubectl logs job/<name> -n <ns>` |
| `CAPTenant` stuck in `Provisioning` | `CAPTenantOperation` job failed | `kubectl describe captenantoperation -n <ns>`, then `kubectl logs job/<name> -n <ns>` for the failed tenant operation job |
| `CAPApplication` stuck in `WaitingForSecrets` | Referenced BTP service Secrets not present | Inspect the `ServiceInstance`/`ServiceBinding` resources that create them |
| Resource stuck with finalizer after delete | Controller still processing | Wait; check controller logs — do **not** remove finalizers manually |
| `@sap/cds-mtxs` security context error | Wrong `runAsUser` | Set `securityContext.runAsUser` in `jobDefinition` |
| Approuter can't reach CAP backend | Missing destination mapping | Add `destinationName` to the CAP workload in `CAPApplicationVersion` |
| Approuter requests time out | No destination timeout configured | Set `destinations` env var timeout on the Approuter workload |
| Credentials not injected | Service not in `consumedBTPServices` | Verify service name matches `CAPApplication.spec.btp.services[].name` |
| Tenant jobs fail with SAP HANA connection errors | Consumer-side HANA config | Check entitlements, inbound connections, cluster-to-subaccount mapping |
| Controller OOM-killed / high memory | Large number of cluster Secrets cached | Increase the controller workload memory limit |

## `@sap/cds-mtxs` security context error

CAP Operator uses the `@sap/cds-mtxs` library by default for CLI-based tenant provisioning, deprovisioning, and upgrade operations. (The older `@sap/cds-mtx` wrapper, previously selectable via `IS_MTXS_ENABLED=false`, has been removed along with CDS v6 support.)

Depending on your cluster hardening setup, you may need to add a `securityContext` to the `TenantOperation` and `CAP` workloads:

```yaml
- name: tenant-job
  consumedBTPServices:
  - "{{ include "xsuaaInstance" . }}"
  - "{{ include "serviceManagerInstance" . }}"
  - "{{ include "saasRegistryInstance" . }}"
  jobDefinition:
    type: TenantOperation
    env:
    - name: CDS_ENV
      value: production
    image: "some.repo.example.com/cap-app/server"
    securityContext: # needed until CAP resolves folder creation in the container root dir at runtime
      runAsUser: 1000
```

## Secret and credential handling

`xsenv`/`cds` handle credentials differently on Kubernetes than on Cloud Foundry. When credential data is read directly from Secrets, JSON type information can be lost, causing inconsistencies.

The SAP Service Binding Specification addresses this by requiring metadata on the Secret. Both `btp-service-operator` and `cf-service-operator` support adding this metadata. Where it is not used, CAP Operator creates a `VCAP_SERVICES` environment variable across all workloads and expects all BTP service credentials stored under a `credentials` key in the Secret.

Set this with the `secretKey` property on the `ServiceBinding`:

```yaml
apiVersion: cf.cs.sap.com/v1alpha1
kind: ServiceBinding
metadata:
  name: uaa
  namespace: demo
spec:
  serviceInstanceName: uaa
  name: app-uaa
  secretKey: credentials
```

> Use `secretKey` even when credential metadata is available — it reduces the overhead of parsing multiple JSON attributes.

## Approuter does not forward requests to the application server

The Approuter maps incoming requests to configured destinations. If you use an `xs-app.json` file to map routes, ensure the `destinationName` for the CAP back end is specified in the corresponding `CAPApplicationVersion` configuration. CAP Operator injects this destination into the Approuter pods via environment variables.

## Approuter requests time out for long-running back-end operations

If a back-end service takes a long time to respond, configure the `destinations` environment variable on the Approuter to set the desired timeout for that destination (`destinationName`). CAP Operator overwrites only the URL part of the destination to point to the correct workload; all other settings are preserved.

## Supported Approuter version

Use `@sap/approuter` version `14.x.x` or higher.

## CAP Operator resources cannot be deleted

All CRs created by CAP Operator are protected with `finalizers` to ensure proper cleanup. Never remove finalizers manually.

**As of v0.34.0**, deleting a `CAPApplication` moves it to a `Deleting` state and waits until all `CAPTenant` resources are removed before proceeding. Consumer tenants must be cleaned up by unsubscribing from the application (via the SAP BTP cockpit or SaaS Provisioning service APIs); the provider tenant is automatically deleted. Once all tenants are gone, deletion of the `CAPApplication` and its remaining child resources proceeds automatically. (Prior to v0.34.0, deleting a `CAPApplication` automatically triggered deprovisioning of all tenants.)

> **Important:** CAP Operator requires the Secrets from service instances and bindings to exist for the entire lifecycle of the application. Removing service instances, bindings, or their Secrets while CAP application CRs still exist leaves orphaned resources (and potentially orphaned database data), and recovery from such states may not be possible. This easily happens with `helm uninstall`, where deletion order is not configurable — ensure service instance/binding Secrets are not deleted before all dependent CAP application resources are fully removed.

## `CAPApplication` stuck with reason `WaitingForSecrets`

This state means one or more Secrets referenced under `spec.btp.services` are not present in the cluster. CAP Operator cannot resolve this itself — the Secrets are owned and created by an external operator (for example, the [SAP BTP Service Operator](https://github.com/SAP/sap-btp-service-operator)).

Inspect the resources responsible for creating the missing Secrets — typically `ServiceInstance` and `ServiceBinding` resources of the BTP service operator — and check their status for errors or failed conditions explaining why the Secret was not created.

## Tenant operations or jobs fail with SAP HANA connection errors

If `CAPTenantOperation` jobs or other pods fail with SAP HANA connection errors, the issue is outside the scope of CAP Operator. Check the following on the consumer side:

- **Entitlements** — ensure the subaccount has the required entitlements for SAP HANA Cloud/schema.
- **Connection configuration** — verify the HANA instance allows inbound connections from the Kubernetes cluster (IP allowlist / allowed connections in the HANA Cloud configuration).
- **Cluster-to-subaccount mapping** — SAP HANA Cloud requires the Kubernetes cluster to be explicitly mapped to the environment context where the HANA instance runs. This mapping is done per cluster and can optionally be scoped to a namespace. See the [SAP HANA Cloud Administration Guide — Map SAP HANA Database to Another Environment Context](https://help.sap.com/docs/hana-cloud/sap-hana-cloud-administration-guide/map-sap-hana-database-to-another-environment-context?ai=true).

## Controller memory limits on clusters with many Secrets

CAP Operator relies on a global informer cache that watches Secrets across the entire cluster. It does not currently support namespace-scoped caching or namespace exclusion. On clusters with a large number of Secrets, the controller pod may consume significant memory.

If the controller pod is being OOM-killed or shows high memory usage, increase the memory limit of the CAP Operator controller workload in your Helm values to accommodate the full set of cluster Secrets cached at runtime.

See `website/content/en/docs/troubleshoot/_index.md` | [Troubleshooting](https://sap.github.io/cap-operator/docs/troubleshoot/).
