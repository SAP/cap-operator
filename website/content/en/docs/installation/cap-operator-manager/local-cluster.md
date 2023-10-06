---
title: "Local Cluster"
linkTitle: "Local Cluster"
weight: 10
type: "docs"
tags: ["setup"]
description: >
  How to install CAP Operator using CAP Operator Manager in a local cluster
---

## Install CAP Operator Manager
To install the latest version of CAP Operator Manager, please execute the following command:

```bash
kubectl apply -f https://github.com/SAP/cap-operator-lifecycle/releases/latest/download/manager_manifest.yaml
```

This would create namespace `cap-operator-system` with CAP Operator Manager installed. 

## Install CAP Operator using CAP Operator Manager
Once the CAP Operator Manager is running, you can install CAP operator by executing the following command:

```bash
kubectl apply -n cap-operator-system -f https://github.com/SAP/cap-operator-lifecycle/releases/latest/download/manager_default_CR.yaml
```
**This would work only if the `ingressGatewayLabels` in your clusters matches the following values**

```yaml
  ingressGatewayLabels:
    - name: istio
      value: ingressgateway
    - name: app
      value: istio-ingressgateway
```

If not, you will have to manually create the `CAPOperator` resource. For more details, refer to [link](https://sap.github.io/cap-operator-lifecycle/docs/installation/local-cluster/).