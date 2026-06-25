---
title: "Domain Management"
linkTitle: "Domain Management"
weight: 25
type: "docs"
tags: ["domains"]
description: >
  Enhancing Domain Management with CAP Operator
sidebar_root_for: self
---

CAP Operator manages networking for CAP applications through [`Domain`](../resources/domain) and [`ClusterDomain`](../resources/clusterdomain) resources. These resources control TLS handling, ingress routing, and DNS setup for your application's domains. A `CAPApplication` references them via `domainRefs`.

## Domain Resources

Use a `Domain` resource for a domain that belongs to a specific application namespace. The operator creates the `Gateway` and `DNSEntry` in that namespace. The `Certificate` placement depends on the certificate manager in use — see the [`Domain` resource reference](../resources/domain) for details.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain
metadata:
  namespace: cap-app-01
  name: cap-app-01-primary
spec:
  domain: my.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple    # Simple (default), Mutual, or OptionalMutual
  dnsMode: Wildcard  # None (default), Wildcard, Subdomain, or Custom
```

The `dnsTarget` field is optional. If omitted, the target is derived from the Istio Ingress Gateway selected by `ingressSelector`.

## ClusterDomain Resources

Use a `ClusterDomain` resource for a domain shared across multiple applications or namespaces. The operator creates the `Gateway` and `DNSEntry` in the CAP Operator installation namespace. The `Certificate` placement depends on the certificate manager in use — see the [`ClusterDomain` resource reference](../resources/clusterdomain) for details.

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
  tlsMode: Simple      # Simple (default) or Mutual
  dnsMode: Subdomain   # None (default), Wildcard, Subdomain, or Custom
```

When X509 client authentication is required (`tlsMode: Mutual` or `OptionalMutual`), provide additional CA certificates for Istio to verify client certificates via `certConfig.additionalCACertificate`.

## Referencing Domains in CAPApplication

Once your `Domain` and `ClusterDomain` resources are defined, reference them in the `CAPApplication` spec using `domainRefs`:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  domainRefs:
  - kind: Domain
    name: cap-app-01-primary     # Namespaced Domain resource
  - kind: ClusterDomain
    name: common-external-domain # Shared ClusterDomain resource
```

The first entry in `domainRefs` is treated as the primary domain. You can mix `Domain` and `ClusterDomain` references in the same application.

---

## Migration

<details>
<summary>Migrating from the deprecated <code>domains</code> section</summary>

<br>

### Update Your Application Manifests
Earlier versions of CAP Operator used an inline `domains` section directly in `CAPApplication`. This section is deprecated and no longer supported. If you are still using it, migrate to `domainRefs` as described below.

#### Before: deprecated `domains` section
```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  domains:
    istioIngressGatewayLabels:
    - name: app
      value: istio-ingressgateway
    - name: istio
      value: ingressgateway
    primary: my.cluster.shoot.url.k8s.example.com
    secondary:
      - my.example.com
```

#### After: `domainRefs` with explicit resources
Create the `Domain` and `ClusterDomain` resources manually (see sections above), then update your `CAPApplication` to use `domainRefs`.

<br>

### Mutation Webhook
A mutation webhook ensures consistency: if a `CAPApplication` is submitted with a `domains` section, the webhook converts it to `Domain`/`ClusterDomain` resources and populates `domainRefs` automatically.

{{% alert color="warning" title="Warning" %}}
The webhook rejects updates that reintroduce the deprecated `domains` section. If you add or modify the `domains` section in your manifest, the webhook rejects the change and provides an error message instructing you to use `domainRefs` instead.
{{% /alert %}}

### Automatic Migration (v0.15.0 – v0.25.0)
{{% alert color="warning" title="Note" %}}
The automatic migration routine was available from [v0.15.0](https://github.com/SAP/cap-operator/releases/tag/v0.15.0) through [v0.25.0](https://github.com/SAP/cap-operator/releases/tag/v0.25.0) and has been removed as of v0.26.0. If you need this migration, first upgrade to v0.25.0 (or lower), allow the migration to complete, and then upgrade to the latest release.
{{% /alert %}}

Upgrading to CAP Operator v0.15.0 through v0.25.0 triggered an automatic migration routine that:
- Scanned existing `CAPApplication` resources.
- Removed network-related resources (Gateways, DNSEntries, Certificates) linked to the deprecated `domains`.
- Created equivalent `Domain` or `ClusterDomain` resources.
- Updated `CAPApplication` resources to use `domainRefs`.

<br>

### Verify Migration
After migrating, confirm the resources are in the expected state:
```bash
kubectl get capapplication -n <your-app-namespace> <your-ca-name> -o yaml
```

Ensure that:
- The `domains` section is absent.
- The `domainRefs` entries are present.
- The corresponding `Domain` or `ClusterDomain` resources exist in the cluster.

</details>
