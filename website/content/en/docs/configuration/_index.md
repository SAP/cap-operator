---
title: "Configuration"
linkTitle: "Configuration"
weight: 30
type: "docs"
tags: ["setup"]
description: >
  Configuration options
---

This page provides a list of environment variables used by the CAP Operator.

### Controller

- `CERT_MANAGER`: Specifies the certificate manager to be used for TLS certificates. Possible values are:
  - `gardener`: [SAP Gardener Certificate Management](https://github.com/gardener/cert-management)
  - `cert-manager.io`: [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager)
- `DNS_MANAGER`: Specifies the External DNS Manager to be used. Possible values are:
  - `gardener`: [SAP Gardener External DNS Manager](https://github.com/gardener/external-dns-management)
  - `kubernetes`: [External DNS Management from Kubernetes](https://github.com/kubernetes-sigs/external-dns)
