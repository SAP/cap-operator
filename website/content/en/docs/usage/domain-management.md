---
title: "Domain Management"
linkTitle: "Domain Management"
weight: 50
type: "docs"
description: >
  Enhancing Domain Management with CAP Operator
---

The CAP Operator has introduced a significant update in domain management by deprecating the `domains` section in `CAPApplication` resources. This has been replaced with the more flexible `domainRefs`, allowing users to reference `Domain` or `ClusterDomain` resources.

This change empowers users with greater control over how CAP applications interact with external networks, including TLS handling, ingress routing, and DNS setup.

## Migration Support

### Automatic Migration During Upgrade

When upgrading to CAP Operator version [v0.15.0](https://github.com/SAP/cap-operator/releases/tag/v0.15.0), an automatic migration routine will be executed. This routine will:

- Scan existing `CAPApplication` resources.
- Remove network-related resources (Gateways, DNSEntries, Certificates) linked to the deprecated `domains`.
- Create equivalent `Domain` or `ClusterDomain` resources.
- Update `CAPApplication` to utilize `domainRefs`.

### Mutation Webhook

A mutation webhook is also in place to manage `CAPApplication` resources created or updated with the deprecated `domains` section. It transforms these into `Domain` or `ClusterDomain` resources and populates `domainRefs`.

{{< alert color="warning" title="Warning" >}}
The webhook ensures consistency by rejecting updates to deprecated `domains` sections, promoting the transition to `domainRefs`.

**Specifically:**
If you reintroduce and modify the `domains` section in your K8s deployment manifest, the webhook will reject the change with an error message instructing you to use the new `domainRefs` field instead. This is done to maintain consistency and encouraging the adoption of updated domain management practices.
{{< /alert >}}


## Post-Migration Steps

### Verify Migrated Resources

After upgrading, verify your `CAPApplication` resources to ensure `domainRefs` have been added:

```bash
kubectl get capapplication -n <your-app-namespace> <your-ca-name> -o yaml
```

Ensure that:
- the `domains` section is removed
- `domainRefs` entries exist
- corresponding `Domain` or `ClusterDomain` resources are present


### Update Your Application Manifests

If your CAP applications are still using the deprecated `domains` field, you will need to migrate to the new `domainRefs` format and define `Domain` or `ClusterDomain` resources explicitly.

*Before (deprecated domains field):*
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

*After (using domainRefs):*
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

Embrace these changes to enhance your domain management capabilities with CAP Operator.
