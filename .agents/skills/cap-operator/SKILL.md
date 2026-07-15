---
name: cap-operator
description: Manage the lifecycle of multi-tenant SAP CAP applications on Kubernetes using CAP Operator custom resources (CAPApplication, CAPApplicationVersion, CAPTenant, Domain, ClusterDomain). Use when deploying, upgrading, configuring domains, rotating credentials, or troubleshooting CAP Operator-managed apps.
license: Apache-2.0
compatibility: Requires kubectl access to a Kubernetes cluster with CAP Operator installed (sme.sap.com/v1alpha1 CRDs). If kubectl commands return "No resources found" or "the server doesn't have a resource type", verify CAP Operator is installed by running `kubectl get crd | grep sme.sap.com`. If no CRDs are listed, direct the user to install CAP Operator before proceeding.
metadata:
  author: SAP
  project: https://sap.github.io/cap-operator
  api-group: sme.sap.com/v1alpha1
allowed-tools: Bash(kubectl:*)
---

# CAP Operator Skill

Manages the lifecycle of multi-tenant SAP Cloud Application Programming Model (CAP) applications on Kubernetes via the CAP Operator controller.

Full docs: `website/content/en/docs/` | API reference: `website/content/en/docs/reference/` | Website: https://sap.github.io/cap-operator

## Custom Resources

| Resource | Scope | Purpose |
|---|---|---|
| `CAPApplication` | Namespaced | High-level app: BTP services, domain refs, provider subaccount |
| `CAPApplicationVersion` | Namespaced | Immutable version: images, workloads, tenant operation steps |
| `CAPTenant` | Namespaced | A subscribed consumer tenant — controller-managed only |
| `CAPTenantOperation` | Namespaced | Orchestrates provisioning/upgrade/deprovisioning — auto-created |
| `Domain` | Namespaced | Istio Gateway + TLS + DNS for one application |
| `ClusterDomain` | Cluster | Shared domain config across applications |

**Critical rules:**
- `CAPApplicationVersion` is **immutable** after creation. To upgrade, create a new resource with a higher semantic version.
- `CAPTenant` must **never** be created or deleted manually — managed by the subscription server only.
- `CAPTenantOperation` is auto-created by the controller — do not create or delete manually.
- Never remove finalizers from CAP Operator resources manually.

## Common Operations

### Deploy a new application
1. Create `Domain` or `ClusterDomain`
2. Create `CAPApplication` (references BTP services + domain)
3. Create `CAPApplicationVersion` (images + workloads)

See [deploy reference](references/deploy.md) for full YAML examples.

### Upgrade to a new version
Create a **new** `CAPApplicationVersion` with a higher semantic version — do not edit the existing one.
The controller automatically upgrades all tenants and updates Istio `VirtualService` routing.

See [upgrade reference](references/upgrade.md) for details and `tenantOperations` / `contentJobs` configuration.

### Check status
```bash
kubectl get capapplication,capapplicationversion,captenant,captenantoperation -n <namespace>
kubectl describe capapplication <name> -n <namespace>
kubectl get domain,clusterdomain -A
```

**Status flows:**
- `CAPApplicationVersion`: `Processing` → `Ready` | `Error`
- `CAPTenant`: `Provisioning` → `Ready` | `Upgrading` → `Ready` | `Deleting`
- `CAPTenantOperation`: `Processing` → `Completed` | `Failed`

### Domain management
- `Domain` — namespace-scoped, one application. `ClusterDomain` — cluster-scoped, shared.
- TLS modes: `Simple` (default), `Mutual`, `OptionalMutual` (Domain only)
- DNS modes: `None` (default), `Wildcard`, `Subdomain`, `Custom`
- First entry in `domainRefs` is the primary domain.
- `domains` inline section in `CAPApplication` was removed in v0.26.0; use `domainRefs` instead.

See [domain reference](references/domain.md).

### Service exposures (tenant-agnostic)
Use `serviceExposures` in `CAPApplicationVersion` to expose workloads at fixed subdomains independent of tenant routing. Order routes most-specific-first.

See [service exposure reference](references/service-exposure.md).

### Credential rotation rollout
Set `rolloutOnCredentialUpdate: true` on `CAPApplication` to auto-restart workloads when BTP service credential Secrets change. Uses rolling restart (zero downtime). Keep old credentials valid for **at least 24 hours** after issuing new ones.

See [credential rotation reference](references/credential-rotation.md).

### Version cleanup (monitoring-based)
Enable with annotation `sme.sap.com/enable-cleanup-monitoring: "true"` on `CAPApplication`. Configure `deletionRules.expression` (PromQL) on a workload's `monitoring` section; when the expression evaluates to `true` the version is eligible for deletion.

## Key Annotations

| Annotation | Resource | Effect |
|---|---|---|
| `sme.sap.com/enable-cleanup-monitoring: "true"` | `CAPApplication` | Enable monitoring-based version cleanup |
| `sme.sap.com/enable-version-affinity: "true"` | `CAPApplication` | Keep users on current version until logout (experimental) |
| `sme.sap.com/logout-endpoint: "<path>"` | `CAPApplicationVersion` | Custom logout path for version affinity |

## Troubleshooting

| Symptom | Likely Cause | Action |
|---|---|---|
| `CAPApplicationVersion` stuck in `Processing` | Content job failing | `kubectl logs job/<name> -n <ns>` |
| `CAPTenant` stuck in `Provisioning` | `CAPTenantOperation` job failed | `kubectl describe captenantoperation -n <ns>` followed by `kubectl logs job/<name> -n <ns>` for the relevant failed tenant operation job|
| Resource stuck with finalizer after delete | Controller still processing | Wait; check controller logs — do NOT remove finalizers manually |
| `@sap/cds-mtxs` security context error | Wrong `runAsUser` | Set `securityContext.runAsUser` in `jobDefinition` |
| Approuter can't reach CAP backend | Missing `routerDestinationName` | Add `routerDestinationName` to the CAP workload port definition |
| Credentials not injected | Service not in `consumedBTPServices` | Verify service name matches `CAPApplication.spec.btp.services[].name` |

More: `website/content/en/docs/troubleshoot/_index.md`

## Controller Configuration

Tuned via env vars on the controller deployment. Key variables:

| Variable | Purpose |
|---|---|
| `CERT_MANAGER` | `gardener` or `cert-manager.io` |
| `DNS_MANAGER` | `gardener` or `kubernetes` |
| `MAX_CONCURRENT_RECONCILES_CAP_APPLICATION` | CAPApplication reconciliation concurrency |
| `MAX_CONCURRENT_RECONCILES_CAP_APPLICATION_VERSION` | CAPApplicationVersion reconciliation concurrency |
| `MAX_CONCURRENT_RECONCILES_CAP_TENANT` | CAPTenant reconciliation concurrency |
| `MAX_CONCURRENT_RECONCILES_CAP_TENANT_OPERATION` | CAPTenantOperation reconciliation concurrency |

Full list: `website/content/en/docs/configuration/_index.md`
