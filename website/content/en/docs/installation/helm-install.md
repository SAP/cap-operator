---
title: "Using Helm"
linkTitle: "Using Helm"
weight: 20
type: "docs"
tags: ["setup"]
description: >
  How to deploy using Helm chart
---

The recommended way to install the CAP operator components is using the [Helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) which is published in as an OCI package here: oci://ghcr.io/sap/cap-operator-helm/cap-operator.

To install create a namespace and helm install the chart into it. You need to supply your `domain` and the `dnsTarget` of your subscription server, either as command line parameter or with a values file:

Command line parameters:

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-helm/cap-operator --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
```

Values file:

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-helm/cap-operator -f my-cap-operator-values.yaml
```

with a values file `my-cap-operator-values.yaml` like

```yaml
subscriptionServer:
    dnsTarget: public-ingress.<CLUSTER-DOMAIN>
    domain: cap-operator.<CLUSTER-DOMAIN>   
```

Note:
This uses your existing docker credentials, if any. Alternatively, you can pass the desired credentials with options `username` and `password`:

```bash
 helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-helm/cap-operator --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN> --username <ARTIFACTORY-USER> --password <ARTIFACTORY-API-TOKEN>
```

To utilize the [local version](https://github.com/sap/cap-operator-lifecycle/tree/main/chart), use

```bash
helm upgrade -i -n cap-operator-system cap-operator PATH_TO_CAP_OPERATOR_LIFECYCLE_REPOSITORY/chart --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
```

or

```bash
helm upgrade -i -n cap-operator-system cap-operator PATH_TO_CAP_OPERATOR_LIFECYCLE_REPOSITORY/chart -f my-values.yaml
```

{{% include "includes/chart-values.md" %}}
