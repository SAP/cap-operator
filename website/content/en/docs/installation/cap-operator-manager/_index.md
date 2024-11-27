---
title: "Using CAP Operator Manager"
linkTitle: "Using CAP Operator Manager"
weight: 30
type: "docs"
tags: ["setup"]
description: >
  How to install CAP Operator using CAP Operator Manager in a Kubernetes cluster
---

To install the CAP Operator using CAP Operator Manager, please execute the following commands:

```bash
kubectl apply -f https://github.com/SAP/cap-operator-lifecycle/releases/latest/download/manager_manifest.yaml
```

The above command will create namespace `cap-operator-system` with CAP Operator Manager installed. Once the CAP Operator Manager pod is running, you can install the CAP operator by executing the following command:

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

If not, you will have to manually create the `CAPOperator` resource. For more details on the same, please refer to [link](https://sap.github.io/cap-operator-lifecycle/docs/installation/local-cluster/).
