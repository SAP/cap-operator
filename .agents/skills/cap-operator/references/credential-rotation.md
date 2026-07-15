# Credential Rotation Rollout

Automatically restart workloads when BTP service credentials are rotated.

## Enable on CAPApplication

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  rolloutOnCredentialUpdate: true   # opt-in; defaults to false
  btpAppName: cap-app-01
  btp:
    services: # ...
```

## How it works

1. The operator watches all BTP service credential Secrets in the namespace.
2. When a Secret changes, it waits out a batching window (`ROLLOUT_DELAY`, default `1h`).
3. It restarts only the `Deployment` workloads that declare the updated service in `consumedBTPServices` — using a rolling restart (zero downtime).

## Key constraints

- Only `Deployment` workloads are restarted. Content and TenantOperation jobs are unaffected.
- All `CAPApplicationVersion` resources currently serving tenants are covered, not just the latest.
- Keep old credentials valid for **at least 24 hours** after issuing new ones — do not revoke until all pods have restarted with the new credentials.
- The batching window is configurable via the `ROLLOUT_DELAY` env var on the controller deployment (minimum `30s`).

See `website/content/en/docs/usage/rollout-on-credential-update.md`.
