---
title: "ClusterDomain"
linkTitle: "ClusterDomain"
weight: 70
type: "docs"
tags: ["domains"]
description: >
  How to configure the `ClusterDomain` resource
---

A `ClusterDomain` resource is cluster-scoped and intended for domains shared across multiple applications or namespaces. All sub-resources — Gateway, DNSEntry, and (with Gardener certificate manager) the Certificate — are created in the namespace where CAP Operator is installed.

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
  tlsMode: Simple       # Simple (default), Mutual, or OptionalMutual
  dnsMode: Subdomain    # None (default), Wildcard, Subdomain, or Custom
  dnsTarget: public-ingress.cluster.domain  # Optional
  certConfig:           # Optional; only relevant when tlsMode is Mutual or OptionalMutual
    additionalCACertificate: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

### Fields

**`domain`** — the DNS domain name. The TLS certificate is issued for the wildcard `*.domain`.

**`ingressSelector`** — label selector used to locate the Istio Ingress Gateway pods. The operator discovers the gateway's namespace and load balancer service from these pods, and applies the selector to the Istio `Gateway` resource.

**`tlsMode`** — TLS mode for the Istio Gateway:
- `Simple` (default) — server-side TLS only.
- `Mutual` — mutual TLS; client certificate required.
- `OptionalMutual` — mutual TLS; client certificate optional.

**`dnsMode`** — controls DNS entry creation (Gardener external-dns-management only; ignored otherwise):
- `None` (default) — no DNS entries created.
- `Wildcard` — creates a single `*.domain` entry pointing to `dnsTarget`.
- `Subdomain` — creates `<subdomain>.domain` entries for each subdomain observed across referencing applications.
- `Custom` — creates entries defined by `dnsTemplates`; each template has a `name` and `target` field rendered as Go templates. Available variables: `{{.domain}}`, `{{.dnsTarget}}`, `{{.subDomain}}`. See [Custom DNS Templates](../domain-management/custom-dns) for details.

**`dnsTarget`** *(optional)* — the load balancer hostname or IP address to use as the DNS target. Resolved in order: explicit `dnsTarget` field → `DNS_TARGET` environment variable → load balancer service annotation on the Istio Ingress Gateway service.

**`certConfig.additionalCACertificate`** *(optional)* — PEM-encoded CA certificate Istio uses to verify client certificates when `tlsMode` is `Mutual` or `OptionalMutual`. See [Configuring Additional CA Certificates](../domain-management/additional-ca) for details.

**`certConfig.certManager.issuerRef`** *(optional, cert-manager only)* — overrides the cert-manager issuer used to sign the TLS certificate. Defaults to a `ClusterIssuer` named `cluster-ca`. See [Configuring cert-manager Certificates](../domain-management/cert-manager-config) for details.

### Created resources

Sub-resources are mainly created in the CAP Operator namespace:

- Istio `Gateway` — always created.
- `DNSEntry` — Gardener DNS manager only.
- `Certificate` (Gardener cert-manager) — the certificate's `secretRef` points to the Istio Ingress Gateway namespace, which supports cross-namespace secret references.
- `Certificate` (cert-manager) — created in the Istio Ingress Gateway namespace; cert-manager does not support cross-namespace secret references.
- CA certificate `Secret` — created in the Istio Ingress Gateway namespace; only when `certConfig.additionalCACertificate` is set.
