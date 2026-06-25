---
title: "Custom DNS Templates"
linkTitle: "Custom DNS"
weight: 20
type: "docs"
tags: ["domains"]
description: >
  How to configure Custom DNS mode for `Domain` or `ClusterDomain`
---

When `dnsMode` is set to `Custom`, the operator creates DNS entries according to the `dnsTemplates` field instead of the fixed patterns used by `Wildcard` and `Subdomain` modes. This lets you generate multiple DNS records per domain, map subdomains to external names, or combine wildcard and per-subdomain entries in one resource.

{{% alert color="info" title="Prerequisite" %}}
DNS entry creation requires the Gardener external-dns-management controller. When using the Kubernetes DNS manager, `dnsMode` is ignored and no DNS entries are created regardless of the mode chosen.
{{% /alert %}}

## Templates

Each entry in `dnsTemplates` produces one or more DNS records. Up to 10 templates are allowed per resource. The `name` and `target` fields are rendered using [Go templates](https://pkg.go.dev/text/template). A template has two fields:

| Field | Description |
|---|---|
| `name` | DNS name for the record — rendered as a Go template |
| `target` | DNS target (hostname or IP) — rendered as a Go template |

### Available variables

The following variables are available in both `name` and `target`:

| Variable | Value |
|---|---|
| `{{.domain}}` | The value of `spec.domain` |
| `{{.dnsTarget}}` | The effective ingress target: `spec.dnsTarget`, or `DNS_TARGET` env var, or the load balancer service annotation on the Istio Ingress Gateway |
| `{{.subDomain}}` | A subdomain collected from referencing applications — see [Subdomain expansion](#subdomain-expansion) |

Functions from the [Slim Sprig library](https://go-task.github.io/slim-sprig/) are available in all templates.

### Subdomain expansion

When `{{.subDomain}}` appears in a template's `name`, the operator expands that template once for each subdomain observed across all `CAPApplication` resources that reference the domain. A template whose `name` does not contain `{{.subDomain}}` is rendered exactly once.

Subdomains are collected from two sources and tracked in `CAPApplication.status.observedSubdomains`:

- `CAPTenant.spec.subDomain` — each tenant's subdomain
- `CAPApplicationVersion.spec.serviceExposures[].subDomain` — subdomains declared in version service exposures

`{{.subDomain}}` may also be used in `target`, but only when `name` also contains `{{.subDomain}}`.

{{% alert color="warning" title="Subdomain conflicts" %}}
If the same subdomain appears in two different `CAPApplication` resources that both reference the same domain, that subdomain is skipped for the second application and a `SubdomainAlreadyInUse` warning event is raised on it.
{{% /alert %}}

## Example

The following configuration combines a wildcard record with per-subdomain records on the primary domain, and a CNAME chain that maps each subdomain on an external domain to the corresponding subdomain on the primary domain:

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
  dnsMode: Custom
  dnsTemplates:
  - name: '*.{{ .domain }}'
    target: '{{ .dnsTarget }}'
  - name: '{{ .subDomain }}.{{ .domain }}'
    target: '{{ .dnsTarget }}'
  - name: '{{ .subDomain }}.myapp.com'
    target: '{{ .subDomain }}.{{ .domain }}'
```

For an application with subdomains `tenant-a` and `tenant-b`, this produces five DNS records:

| DNS name | Target |
|---|---|
| `*.my.cluster.shoot.url.k8s.example.com` | `<ingress target>` |
| `tenant-a.my.cluster.shoot.url.k8s.example.com` | `<ingress target>` |
| `tenant-b.my.cluster.shoot.url.k8s.example.com` | `<ingress target>` |
| `tenant-a.myapp.com` | `tenant-a.my.cluster.shoot.url.k8s.example.com` |
| `tenant-b.myapp.com` | `tenant-b.my.cluster.shoot.url.k8s.example.com` |
