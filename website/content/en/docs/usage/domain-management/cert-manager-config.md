---
title: "Configuring cert-manager Certificates"
linkTitle: "cert-manager Config"
weight: 30
type: "docs"
tags: ["domains", "cert-manager"]
description: >
  How to configure cert-manager `IssuerRef` for TLS certificates on `Domain` or `ClusterDomain`
---

When the operator is installed with the **cert-manager** certificate manager (configured via the [`CERT_MANAGER` environment variable](../../../configuration#controller)), it creates a cert-manager `Certificate` resource for each `Domain` or `ClusterDomain`. Every `Certificate` must reference an issuer. By default the operator uses a `ClusterIssuer` named `cluster-ca`. Use `certConfig.certManager.issuerRef` to override this with any issuer available in your cluster.

## Default behavior

If `certConfig.certManager` is not set, the operator uses the following issuer reference:

| Field | Default |
|---|---|
| `name` | `cluster-ca` |
| `kind` | `ClusterIssuer` |
| `group` | `cert-manager.io` |

## Configuring a custom issuer

Set `certConfig.certManager.issuerRef` on a `Domain` or `ClusterDomain` to point to any cert-manager issuer:

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain                 # also applies to ClusterDomain
metadata:
  namespace: cap-app-01
  name: cap-app-01-primary
spec:
  domain: my.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  certConfig:
    certManager:
      issuerRef:
        name: my-cluster-issuer   # name of the issuer
        kind: ClusterIssuer       # ClusterIssuer or Issuer
        group: cert-manager.io    # optional; defaults to cert-manager.io
```

### `issuerRef` fields

| Field | Required | Description |
|---|---|---|
| `name` | yes | Name of the cert-manager issuer to use |
| `kind` | no | `ClusterIssuer` (cluster-scoped) or `Issuer` (namespace-scoped). Defaults to `Issuer` if omitted |
| `group` | no | API group of the issuer. Defaults to `cert-manager.io` if omitted |

{{% alert color="info" title="Certificate placement" %}}
When using cert-manager, the `Certificate` resource is created in the Istio Ingress Gateway namespace. This differs from the Gardener certificate manager, where the certificate's `secretRef` uses a cross-namespace reference back to the `Domain` namespace.
{{% /alert %}}
