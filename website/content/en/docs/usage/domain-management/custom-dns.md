---
title: "A Guide to Flexibile DNS Configuration"
linkTitle: "Flexible DNS"
weight: 20
type: "docs"
tags: ["domains"]
description: >
  How to configure Custom DNS mode for `Domain` or `ClusterDomain`
---

## Overview
Configuring DNS settings can be a daunting task. However, with Custom DNS mode, you can leverage Go templates to streamline the process. This guide walks you through the essentials of setting up Custom DNS for your `Domain` or `ClusterDomain` resources.

### What is Custom DNS Mode?
Custom DNS mode lets you use [Go templates](https://pkg.go.dev/text/template) to generate DNS entries dynamically. This feature is especially helpful for managing complex DNS configurations with ease. Specify your desired setup in the `dnsTemplates` field. 
You can enhance your templates with functions from the Slim Sprig library, detailed [here](https://go-task.github.io/slim-sprig/).

#### Allowed Variables in DNSTemplate
- **{{.domain}}**: Represents the value of `spec.domain`.
- **{{.dnsTarget}}**: The effective ingress target, specified by `spec.dnsTarget` or derived from `spec.istioIngressSelector`.
- **{{.subDomain}}**: Refers to the subdomain of a CAPTenant or a tenant agnostic workload.


### DNS Record Behavior

- Each template typically results in one DNS record.
- If the name contains **{{.subDomain}}**, a DNS record is created for each valid subdomain from tenants or service exposures.
- **{{.subDomain}}** may appear in the target only if it appears in the name.


### Example Configuration
Below is an example of how to configure Custom DNS mode for a `Domain` resource:


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

This configuration can be applied to both `Domain` and `ClusterDomain` resources, offering flexibility and control over your DNS configurations.
