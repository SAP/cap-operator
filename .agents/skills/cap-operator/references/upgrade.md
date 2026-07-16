# Upgrading to a New Application Version

Create a **new** `CAPApplicationVersion` with a higher semantic version. Never modify an existing one — it is immutable after creation (enforced by webhooks).

## New CAPApplicationVersion

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-2
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-app-01
  version: "1.1.0"               # must be higher than "1.0.0"
  registrySecrets:
    - regcred
  workloads:
    # ... same structure with updated image tags
    - name: notify-upgrade        # example CustomTenantOperation
      consumedBTPServices: []
      jobDefinition:
        type: CustomTenantOperation
        image: <registry>/srv/server:2.0.0
        command: ["npm", "run", "notify:upgrade"]
        backoffLimit: 1
        continueOnFailure: true
  tenantOperations:
    upgrade:
      - workloadName: notify-upgrade
        continueOnFailure: true   # overall upgrade continues even if this step fails
      - workloadName: tenant-operation
    provisioning:
      - workloadName: tenant-operation
    # deprovisioning omitted → only TenantOperation step runs
  contentJobs:                    # execution order for Content jobs
    - service-content
```

## Upgrade sequence (automatic)

1. Controller creates new Deployments and runs Content jobs for the new version.
2. Once the new `CAPApplicationVersion` is `Ready`, the controller sets `version` on all `CAPTenant` resources.
3. Each `CAPTenant` transitions to `Upgrading`; a `CAPTenantOperation` of type `upgrade` is created per tenant.
4. After all tenants complete upgrade, the Istio `VirtualService` per tenant is updated to route to the new version.
5. The old `CAPApplicationVersion` can be deleted once all tenants have upgraded.

## tenantOperations

Defines the ordered steps for `provisioning`, `upgrade`, and `deprovisioning` operations. Each step references a workload by name.

- `continueOnFailure: true` — the overall operation continues even if this step fails.
- If `tenantOperations` is omitted entirely, only the `TenantOperation` workload is run for each operation type.
- `deprovisioning` key is optional; if omitted, only the `TenantOperation` workload runs.

## contentJobs

Defines execution order for `Content` workload jobs when a `CAPApplicationVersion` is created. If omitted, content jobs run in the order they appear in `workloads`.

## Version Affinity (experimental)

Add annotation `sme.sap.com/enable-version-affinity: "true"` to `CAPApplication` to keep users on their current version until logout. Set `sme.sap.com/logout-endpoint: "<path>"` on `CAPApplicationVersion` for a custom logout path (no leading slash).

See `website/content/en/docs/usage/version-upgrade.md` | [Version upgrade](https://sap.github.io/cap-operator/docs/usage/version-upgrade/).
