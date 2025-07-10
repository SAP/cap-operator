---
title: "Domain Management"
linkTitle: "Domain Management"
weight: 50
type: "docs"
description: >
  Enhancing Domain Management with CAP Operator
---

The CAP Operator has introduced a pivotal update in domain management, transitioning from the deprecated `domains` section in `CAPApplication` resources to the more versatile `domainRefs`. This shift allows users to reference [`Domain`](../resources/domain) or [`ClusterDomain`](../resources/clusterdomain) resources, offering enhanced control over CAP applications' networking behaviour, including TLS handling, ingress routing, and DNS setup.

## Update Your Application Manifests

If your CAP applications still use the deprecated `domains` section, you will need to migrate to the new `domainRefs` format and define `Domain` or `ClusterDomain` resources explicitly.

*Before (deprecated domains section):*
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

## Migration Support

### Automatic Migration During Upgrade

Upgrading to CAP Operator version [v0.15.0](https://github.com/SAP/cap-operator/releases/tag/v0.15.0) initiates an automatic migration routine. This process:

- Scans existing `CAPApplication` resources.
- Removes network-related resources (Gateways, DNSEntries, Certificates) linked to the deprecated `domains`.
- Creates equivalent `Domain` or `ClusterDomain` resources.
- Updates `CAPApplication` to utilize `domainRefs`.

### Mutation Webhook

A mutation webhook is also in place to ensure consistency by transforming `CAPApplication` resources created or updated with the deprecated `domains` section into `Domain` or `ClusterDomain` resources, populating `domainRefs`.

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
- `domains` section is removed
- `domainRefs` entries exist
- corresponding `Domain` or `ClusterDomain` resources are present

## Conclusion

Embrace these changes to enhance your domain management capabilities with CAP Operator. Transitioning to `domainRefs` not only streamlines your network interactions but also aligns with the latest practices for efficient domain management.
