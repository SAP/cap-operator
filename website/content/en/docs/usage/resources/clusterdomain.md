---
title: "ClusterDomain"
linkTitle: "ClusterDomain"
weight: 60
type: "docs"
tags: ["domains"]
description: >
  How to configure the `ClusterDomain` resource
---

Here's an example of a fully configured `ClusterDomain` resource:

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

- The `dnsTarget` field is optional. If specified, it will be used; otherwise, it will be derived from the Istio ingress gateway selectors.
- `Gateway` and `DNSEntry` will be created in the cap-operator namespace while the `Certificates` will be created in the `istio-system` namespace.
