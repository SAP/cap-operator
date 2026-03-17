---
title: "Domain Management"
linkTitle: "Domain Management"
weight: 50
type: "docs"
tags: ["domains"]
description: >
  Enhancing Domain Management with CAP Operator
sidebar_root_for: self
---

CAP Operator introduced an update to domain management: the deprecated `domains` section in `CAPApplication` resources has been replaced by the more flexible `domainRefs`. This allows you to reference [`Domain`](../resources/domain) or [`ClusterDomain`](../resources/clusterdomain) resources, giving greater control over networking behavior, including TLS handling, ingress routing, and DNS setup.

## Update Your Application Manifests

If your CAP applications still use the deprecated `domains` section, migrate to the `domainRefs` format by defining `Domain` or `ClusterDomain` resources explicitly.

*Using the deprecated `domains` section:*
```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  ...
  domains:
    istioIngressGatewayLabels:
    - name: app
      value: istio-ingressgateway
    - name: istio
      value: ingressgateway
    primary: my.cluster.shoot.url.k8s.example.com
    secondary:
      - my.example.com
  ...
```

*Using `domainRefs`:*
```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  ...
  domainRefs:
  - kind: Domain
    name: cap-app-01-primary     # Refers to a namespaced Domain resource
  - kind: ClusterDomain
    name: common-external-domain # Refers to a shared ClusterDomain resource
  ...
```
*Define the referenced domain resources:*
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
  tlsMode: Simple
  dnsMode: Wildcard
```
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
  tlsMode: Simple
  dnsMode: Subdomain
```

## Migration Support

### Automatic Migration During Upgrade

{{% alert color="warning" title="Note" %}}
The automatic migration routine described below was available from [v0.15.0](https://github.com/SAP/cap-operator/releases/tag/v0.15.0) through [v0.25.0](https://github.com/SAP/cap-operator/releases/tag/v0.25.0) and has been removed as of v0.26.0. If you need this migration, first upgrade to v0.25.0 (or lower), allow the migration to complete, and then upgrade to the latest release.
{{% /alert %}}

<details>
<summary>Details (v0.15.0 – v0.25.0)</summary>

Upgrading to CAP Operator version v0.15.0 through v0.25.0 triggers an automatic migration routine that:

- Scans existing `CAPApplication` resources.
- Removes network-related resources (Gateways, DNSEntries, Certificates) linked to the deprecated `domains`.
- Creates equivalent `Domain` or `ClusterDomain` resources.
- Updates `CAPApplication` resources to use `domainRefs`.

</details>

### Mutation Webhook

A mutation webhook ensures consistency by converting `CAPApplication` resources that still use the deprecated `domains` section into `Domain` or `ClusterDomain` resources and populating `domainRefs`.

{{% alert color="warning" title="Warning" %}}
The webhook rejects updates that reintroduce the deprecated `domains` section. If you add or modify the `domains` section in your manifest, the webhook rejects the change and provides an error message instructing you to use `domainRefs` instead.
{{% /alert %}}


## Post-Migration Steps

### Verify Migrated Resources

After upgrading, verify your `CAPApplication` resources to confirm that `domainRefs` have been added:

```bash
kubectl get capapplication -n <your-app-namespace> <your-ca-name> -o yaml
```

Ensure that:
- the `domains` section is removed
- the `domainRefs` entries exist
- the corresponding `Domain` or `ClusterDomain` resources are present
