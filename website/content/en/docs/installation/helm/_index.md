---
title: "Using Helm"
linkTitle: "Using Helm"
weight: 20
type: "docs"
tags: ["setup"]
description: >
  How to deploy with Helm charts
---

To install CAP Operator components, use the [Helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) published as an OCI package at `oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator`.

## Installation

Create a namespace and install the Helm chart in that namespace by specifying the `domain` and `dnsTarget` for your subscription server, either:

- ### As command line parameters:
  ```bash
  kubectl create namespace cap-operator-system
  helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
  ```

- ### As a `YAML` values file:
  ```bash
  kubectl create namespace cap-operator-system
  helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator -f my-cap-operator-values.yaml
  ```
  The values file `my-cap-operator-values.yaml` can have the following content:
  ```yaml
  subscriptionServer:
    dnsTarget: public-ingress.<CLUSTER-DOMAIN>
    domain: cap-operator.<CLUSTER-DOMAIN>
  ```

