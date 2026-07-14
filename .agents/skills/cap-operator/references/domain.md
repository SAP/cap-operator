# Domain Management

CAP Operator manages Istio Gateways, TLS certificates, and DNS entries through `Domain` and `ClusterDomain` resources.

## Domain (namespace-scoped)

Use for a domain belonging to one application. The operator creates the `Gateway` and `DNSEntry` in the application namespace.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain
metadata:
  name: cap-app-01-primary
  namespace: cap-app-01
spec:
  domain: my.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple    # Simple (default) | Mutual | OptionalMutual
  dnsMode: Wildcard  # None (default) | Wildcard | Subdomain | Custom
  # dnsTarget is optional; derived from the Ingress Gateway if omitted
```

## ClusterDomain (cluster-scoped)

Use for a domain shared across multiple applications or namespaces. The operator creates the `Gateway` and `DNSEntry` in the CAP Operator installation namespace.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: ClusterDomain
metadata:
  name: common-external-domain
spec:
  domain: my.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple     # Simple (default) | Mutual
  dnsMode: Subdomain  # None (default) | Wildcard | Subdomain | Custom
```

## TLS modes

| Mode | Description |
|---|---|
| `Simple` | Standard one-way TLS (default) |
| `Mutual` | mTLS required — clients must present a certificate |
| `OptionalMutual` | mTLS optional (`Domain` only — not supported on `ClusterDomain`) |

When `tlsMode` is `Mutual` or `OptionalMutual`, provide additional CA certificates via `certConfig.additionalCACertificate`. See `website/content/en/docs/usage/domain-management/additional-ca.md`.

## DNS modes

| Mode | Description |
|---|---|
| `None` | No DNS entry created (default) |
| `Wildcard` | Single wildcard DNS entry (`*.<domain>`) |
| `Subdomain` | Per-tenant subdomain DNS entries |
| `Custom` | Template-based DNS entry — see `website/content/en/docs/usage/domain-management/custom-dns.md` |

## Referencing domains in CAPApplication

```yaml
spec:
  domainRefs:
    - kind: Domain
      name: cap-app-01-primary       # namespace-scoped
    - kind: ClusterDomain
      name: common-external-domain   # cluster-scoped, shared
```

The **first entry** in `domainRefs` is treated as the primary domain. You can mix `Domain` and `ClusterDomain` references.

## Migration from deprecated `domains` section

The inline `domains` section in `CAPApplication` was removed in v0.26.0. Use explicit `Domain`/`ClusterDomain` resources with `domainRefs`.

A mutation webhook will reject any attempt to reintroduce the `domains` section.

**Migration path from < v0.26.0:**
1. Upgrade to v0.25.0 first — this runs the automatic `domains` → `domainRefs` migration.
2. Then upgrade to the latest release.

See `website/content/en/docs/usage/domain-management/_index.md`.
