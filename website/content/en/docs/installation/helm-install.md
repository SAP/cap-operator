---
title: "Using Helm"
linkTitle: "Using Helm"
weight: 20
type: "docs"
tags: ["setup"]
description: >
  How to deploy with Helm charts
---

To install CAP operator components, we recommend that you use the [Helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) that is published as an OCI package here: oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator..

Create a namespace and helm install the chart to it. Supply your `domain` and the `dnsTarget` of your subscription server, either as command line parameter or with a values file:

Command line parameters:

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
```

Values file:

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator -f my-cap-operator-values.yaml
```

with a values file `my-cap-operator-values.yaml` such as

```yaml
subscriptionServer:
    dnsTarget: public-ingress.<CLUSTER-DOMAIN>
    domain: cap-operator.<CLUSTER-DOMAIN>   
```

{{% include "includes/chart-values.md" %}}
