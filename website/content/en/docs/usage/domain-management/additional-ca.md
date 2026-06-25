---
title: "Configuring Additional CA Certificates"
linkTitle: "CA Certificates"
weight: 30
type: "docs"
tags: ["domains"]
description: >
   How to configure Additional CA Certificates for `Domain` or `ClusterDomain`
---

When `tlsMode` is set to `Mutual` or `OptionalMutual` on a `Domain` or `ClusterDomain`, Istio requires a CA certificate to verify client certificates presented during the TLS handshake. Provide this certificate via `certConfig.additionalCACertificate`.

The operator stores the certificate as a Kubernetes `Secret` (key: `ca.crt`) in the Istio Ingress Gateway namespace, where Istio reads it.

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: ClusterDomain          # also applies to Domain
metadata:
  name: cap-example-domain
spec:
  domain: myapp.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Mutual
  certConfig:
    additionalCACertificate: |
      -----BEGIN CERTIFICATE-----
      MIIFZjCCA06gAwIBAgIQGHcPvmUGa79M6pM42bGFYjANBgkqhkiG9w0BAQsFADBN
      ...
      -----END CERTIFICATE-----
```

Removing `certConfig.additionalCACertificate` from the spec causes the operator to delete the corresponding secret.
