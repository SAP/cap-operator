---
title: "Rollout on Credential Update"
linkTitle: "Rollout on Credential Update"
weight: 45
type: "docs"
description: >
  Automatically roll out application workloads when BTP service credentials are rotated
---

When SAP BTP service credentials are rotated — for example, by a credential rotation tool or by re-binding a service instance — the Kubernetes Secrets holding those credentials are updated. By default, running application workloads are **not** restarted and continue to use the old credentials until the next deployment or a manual rollout.

Enabling `rolloutOnCredentialUpdate` on a `CAPApplication` resource instructs CAP Operator to watch the referenced BTP service credential Secrets and automatically trigger a rolling restart of affected Deployments whenever their credentials change.

## Benefits

| Benefit | Description |
|---|---|
| No stale credentials in running pods | Pods pick up fresh credentials without a manual rollout or a new `CAPApplicationVersion`. |
| Selective restarts | Only Deployments that actually consume the updated service are restarted; unaffected workloads are left untouched. |
| Resilient to operator restarts | On startup, CAP Operator re-checks all relevant Secrets so that credential changes that occurred while the operator was down are not missed. |
| Batched processing | Multiple Secret updates arriving within the batching window are accumulated and processed in a single pass, avoiding redundant rollouts. |

## Enabling the Feature

Set `rolloutOnCredentialUpdate: true` in the `CAPApplication` spec:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  rolloutOnCredentialUpdate: true # opt-in to automatic rollout on credential rotation
  btpAppName: cap-app-01
  btp:
    services:
      - class: xsuaa
        name: app-uaa
        secret: cap-app-01-uaa-bind-cf
      - class: saas-registry
        name: app-saas-registry
        secret: cap-app-01-saas-bind-cf
      - class: service-manager
        name: app-service-manager
        secret: cap-app-01-svc-man-bind-cf
  domainRefs:
    - kind: ClusterDomain
      name: common-external-domain
  providerSubaccountId: provider-subaccount-id
```

The field is optional and defaults to `false`. See the [API Reference](../../reference/#sme.sap.com/v1alpha1.CAPApplication) for the full spec.

## How It Works

Once enabled, the operator follows this flow whenever a watched Secret changes:

1. **Secret watch** — CAP Operator watches all Kubernetes Secrets in the namespace of any `CAPApplication` that has `rolloutOnCredentialUpdate: true`. When a Secret is updated, the namespace is scheduled for processing after a configurable batching window (see [Operator Configuration](#operator-configuration)).

2. **Batching** — any additional Secret changes arriving in the same namespace within the batching window are accumulated. When the window expires, all collected changes are processed together in a single pass, preventing redundant rollouts when multiple services are rotated at once.

3. **Affected workload detection** — for each `CAPApplicationVersion` currently in use (the latest ready version, plus any version still serving active tenants), the operator checks which Deployments declare the rotated service in their `consumedBTPServices` list.

4. **VCAP secret comparison** — the operator rebuilds the `VCAP_SERVICES` data for each affected Deployment using the new credential data. If the payload is identical to the existing one, the Deployment is left untouched and no restart is triggered.

5. **Rolling restart** — when the data has changed, a new `VCAP_SERVICES` secret is created and the Deployment's `envFrom` reference is updated to point to it. Kubernetes detects the change and performs a rolling restart of the pods, ensuring zero downtime.

> **Note:** Only Deployments are restarted. Job workloads (content deployers, tenant operation jobs) are not affected by this feature.

> **Note:** The rollout covers all ready `CAPApplicationVersion` resources currently serving tenants, not only the latest version. This ensures credentials are refreshed consistently across all active versions during an upgrade transition.

## Operator Configuration

The batching window duration is configurable via an environment variable on the CAP Operator deployment.

| Environment Variable | Description | Default | Minimum |
|---|---|---|---|
| `ROLLOUT_DELAY` | How long the operator waits after a credential Secret is updated before processing the rollout. Secret changes arriving within this window for the same namespace are batched into a single pass. Accepts any Go duration string (e.g. `30m`, `2h`). | `1h` | `30s` |

If the configured value cannot be parsed, the operator logs an error and falls back to the default (`1h`). If the parsed value is below the minimum (`30s`), the operator logs an error and clamps it to `30s`.


## Recommendations

### Keep Old Credentials Valid Long After Rotation

When rotating credentials, **do not invalidate the old Secret immediately**. CAP Operator needs time to:

1. detect the Secret change,
2. wait out the batching window (`ROLLOUT_DELAY`),
3. rebuild and compare the `VCAP_SERVICES` payload, and
4. wait for Kubernetes to complete the rolling restart of every affected Deployment.

Only once all pods are running with the new credentials is it safe to revoke the old ones.

As a rule of thumb, keep the old credentials valid for **at least 24 hours** after issuing the new ones. This provides a generous buffer that covers the batching delay, the rollout duration, and any transient failures or retries in the operator's reconciliation loop.

Revoking credentials too soon risks pods being restarted mid-rollout with no valid credentials available, which causes application downtime.
