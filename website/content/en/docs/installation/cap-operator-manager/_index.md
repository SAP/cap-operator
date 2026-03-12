---
title: "Using CAP Operator Manager"
linkTitle: "Using CAP Operator Manager"
weight: 30
type: "docs"
tags: ["setup"]
description: >
  How to install CAP Operator using CAP Operator Manager in a Kubernetes cluster
---

To install the CAP Operator using CAP Operator Manager, run the following command:

```bash
kubectl apply -f https://github.com/SAP/cap-operator-lifecycle/releases/latest/download/manager_manifest.yaml
```

This creates the `cap-operator-system` namespace with CAP Operator Manager installed. Once the CAP Operator Manager pod is running, install the CAP Operator by running:

```bash
kubectl apply -n cap-operator-system -f https://github.com/SAP/cap-operator-lifecycle/releases/latest/download/manager_default_CR.yaml
```

**This works only if the `ingressGatewayLabels` in your cluster match the following values:**

```yaml
ingressGatewayLabels:
  - name: istio
    value: ingressgateway
  - name: app
    value: istio-ingressgateway
```

If not, you must create the `CAPOperator` resource manually. For details, see the [documentation](https://sap.github.io/cap-operator-lifecycle/docs/installation/local-cluster/).
