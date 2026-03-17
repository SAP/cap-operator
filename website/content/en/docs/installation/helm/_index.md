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

## Optional steps

- ### Enable Service Monitors for metrics

  To enable monitoring via [metrics](../../usage/operator-metrics) emitted by CAP Operator components, set the following value:
  ```yaml
  monitoring:
    enabled: true # <-- enables creation of service monitors for metrics emitted by CAP Operator components
  ```
  To enable detailed operational metrics for the controller:
  ```yaml
  controller:
      detailedOperationalMetrics: true
  ```
- ### Set up Prometheus integration for _Version Monitoring_

  To use the [Version Monitoring](../../usage/version-monitoring/) feature, provide a [Prometheus](https://prometheus.io/) server URL to the CAP Operator. When installing with the Helm chart, specify the following values:
  ```yaml
  controller:
    versionMonitoring:
      prometheusAddress: "http://prometheus-operated.monitoring.svc.cluster.local:9090" # <-- example of a Prometheus server running inside the same cluster
      promClientAcquireRetryDelay: "2h"
      metricsEvaluationInterval: "30m" # <-- interval at which version metrics are evaluated
  ```
  On startup, the controller attempts to connect to the Prometheus server and fetch [runtime information](https://prometheus.io/docs/prometheus/latest/querying/api/#runtime-information) to verify the connection. If the connection fails, it retries after the delay specified in `controller.versionMonitoring.promClientAcquireRetryDelay`. See default values [here](./helm-values).

  {{% alert title="Note" color="info" %}}
  - When connecting the controller to a Prometheus server running inside the cluster, ensure that the `NetworkPolicies` required for connecting to the service in the Prometheus namespace are also created.
  - If the Prometheus service is configured to use TLS, mount the relevant CA root certificates as volumes to the controller.
  {{% /alert %}}
