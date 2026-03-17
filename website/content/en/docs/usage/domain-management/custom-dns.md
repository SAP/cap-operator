---
title: "A Guide to Flexible DNS Configuration"
linkTitle: "Flexible DNS"
weight: 20
type: "docs"
tags: ["domains"]
description: >
  How to configure Custom DNS mode for `Domain` or `ClusterDomain`
---

## Overview
Custom DNS mode lets you use Go templates to generate DNS entries dynamically, giving you precise control over complex DNS configurations. Specify your desired setup in the `dnsTemplates` field.

You can use functions from the [Slim Sprig library](https://go-task.github.io/slim-sprig/) in your templates.

### What is Custom DNS Mode?
Custom DNS mode uses [Go templates](https://pkg.go.dev/text/template) to generate DNS entries. Specify your configuration in the `dnsTemplates` field.

#### Available Variables in DNS Templates
- **{{.domain}}**: The value of `spec.domain`.
- **{{.dnsTarget}}**: The effective ingress target, specified by `spec.dnsTarget` or derived from `spec.istioIngressSelector`.
- **{{.subDomain}}**: The subdomain of a `CAPTenant` or a tenant-agnostic workload.


### DNS Record Behavior

- Each template typically produces one DNS record.
- If the name contains **{{.subDomain}}**, a DNS record is created for each valid subdomain from tenants or service exposures.
- **{{.subDomain}}** may appear in the target only if it also appears in the name.


### Example Configuration
The following example configures Custom DNS mode for a `Domain` resource:


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
  dnsMode: Custom
  dnsTemplates:
  - name: '*.{{ .domain }}'
    target: '{{ .dnsTarget }}'
  - name: '{{ .subDomain }}.{{ .domain }}'
    target: '{{ .dnsTarget }}'
  - name: '{{ .subDomain }}.myapp.com'
    target: '{{ .subDomain }}.{{ .domain }}'
```

This configuration applies to both `Domain` and `ClusterDomain` resources.
