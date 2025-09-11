---
title: "Domain"
linkTitle: "Domain"
weight: 60
type: "docs"
tags: ["domains"]
description: >
  How to configure the `Domain` resource
---

Here's an example of a fully configured `Domain` resource:

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
  tlsMode: Simple        # Simple (default) or  Mutual or OptionalMutual
  dnsMode: Wildcard      # Custom or Wildcard or Subdomain or None (default)
  dnsTarget: public-ingress.cluster.domain # Optional

```

- The `dnsTarget` field is optional. If specified, it will be used; otherwise, it will be derived from the Istio Ingress Gateway via `ingressSelector`.
- `Gateway` and `DNSEntry` will be created in the same namespace as the `Domain` resource while the `Certificates` will be created in the namespace where Istio Ingress Gateway is present.
- In cases when X509 client authentication is enforced on the Istio Gateway by setting `tlsMode` to `Mutual` or `OptionalMutual`, additional CA certificates are needed by Istio for verifying client certificates. These can be specified in the `certConfig.additionalCACertificate` field.
