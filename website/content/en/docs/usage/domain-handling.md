---
title: "Domain Handling"
linkTitle: "Domain Handling"
weight: 80
type: "docs"
description: >
  How to handle domains
---

The CAP Operator supports a flexible and configurable approach to application networking through two custom resource types: `Domain` and `ClusterDomain`. These resources give users full control over how CAP applications are exposed to external networks, including TLS handling, ingress routing, and DNS setup.

## Resource Specifications

### Domain

The `Domain` resource is namespaced and intended for use by a single application typically for your primary domain. See [API Reference](../../reference/#sme.sap.com/v1alpha1.Domain) for more details.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain
metadata:
  namespace: cap-app-01
  name: cap-app-01-primary
spec:
  domain: cap-app-01.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple        # Simple (default) or  Mutual
  dnsMode: Wildcard      # Wildcard or Subdomain or None (default)
```

### ClusterDomain

The `ClusterDomain` resource is not namespaced and is suited for global or shared domain configurations. For example, multiple applications can share the same secondary domain. See [API Reference](../../reference/#sme.sap.com/v1alpha1.ClusterDomain) for more details.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: ClusterDomain
metadata:
  name: common-secondary-domain
spec:
  domain: alt.shoot.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple        # Simple (default) or  Mutual
  dnsMode: Subdomain     # Wildcard or Subdomain or None (default)
  dnsTarget: public-ingress.cluster.domain # Optional
```

> Note: The `dnsTarget` field is optional. If specified, it will be used; otherwise, it will be derived from the Istio ingress gateway labels.

## CAPApplication Integration

CAPApplication can reference one or more `Domain` or `ClusterDomain` resources using the `domainRefs` field -

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
    name: cap-app-01-primary
  - kind: ClusterDomain
    name: common-secondary-domain
  ...
```
