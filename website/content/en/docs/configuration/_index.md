---
title: "Configuration"
linkTitle: "Configuration"
weight: 30
type: "docs"
tags: ["setup"]
description: >
  How to configure
---

Here's a list of environment variables used by CAP Operator.

### Controller

- `CERT_MANAGER`: specifies the certificate manager to be used for TLS certificates. Possible values are:
  - `gardener`: ["Gardener" certificate management](https://github.com/gardener/cert-management)
  - `cert-manager.io`: [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- `DNS_MANAGER`: specifies the external DNS manager to be used. Possible values are:
  - `gardener`: ["Gardener" external DNS manager](https://github.com/gardener/external-dns-management)
  - `kubernetes`: [external DNS management from Kubernetes](https://github.com/kubernetes-sigs/external-dns)
