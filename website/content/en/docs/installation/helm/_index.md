---
title: "Using Helm"
linkTitle: "Using Helm"
weight: 20
type: "docs"
tags: ["setup"]
description: >
  How to deploy with Helm charts
---

To install CAP operator components, we recommend using the [Helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) that is published as an OCI package at `oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator`.

## Installation

Create a namespace and install the Helm chart in that namespace by specifying the `domain` and the `dnsTarget` for your subscription server, either 

- #### As command line parameters:
  ```bash
  kubectl create namespace cap-operator-system
  helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
  ```

- #### Or as a `YAML` file with the values:
  ```bash
  kubectl create namespace cap-operator-system
  helm upgrade -i -n cap-operator-system cap-operator oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator -f my-cap-operator-values.yaml
  ```
  In this example, the provided values file, `my-cap-operator-values.yaml`, can have the following content:
  ```yaml
  subscriptionServer:
    dnsTarget: public-ingress.<CLUSTER-DOMAIN>
    domain: cap-operator.<CLUSTER-DOMAIN>   
  ```

## (Optional) Setup Prometheus Integration for _Version Monitoring_

To use the Version Monitoring feature of the CAP Operator, a [Prometheus](https://prometheus.io/) server URL can be provided to the CAP Operator. When installing the CAP Operator using the Helm chart, the following values can be specified in the values:
```yaml
controller:
  versionMonitoring:
    prometheusAddress: "http://prometheus-operated.monitoring.svc.cluster.local:9090" # <-- example of a Prometheus server running inside the same cluster
    promClientAcquireRetryDelay: "2h"
    metricsEvaluationInterval: "30m" # <-- duration after which version metrics are evaluated
```
When the controller is started, the operator will try to connect to the Prometheus server and fetch [runtime information](https://prometheus.io/docs/prometheus/latest/querying/api/#runtime-information) to verify the connection. If the connection is not successful, it will be retried after the duration specified as `controller.versionMonitoring.promClientAcquireRetryDelay`. Check default values for these attributes [here](helm-values.md).

{{% alert title="Note" color="info" %}}
- When connecting the controller to a Prometheus server running inside the cluster, please ensure that `NetworkPolicies` required for connecting to the service in the namespace where Prometheus is running are also created.
- If the Prometheus service is configured to use TLS, the relevant CA root certificates which need to be trusted can be mounted as volumes to the controller.
{{% /alert %}}
