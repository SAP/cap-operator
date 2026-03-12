---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  How to prepare the cluster before installing CAP Operator
---

We recommend using a "[Gardener](https://gardener.cloud/)" managed cluster to deploy CAP applications managed with CAP Operator.

Set up the following prerequisites in the Kubernetes cluster before installing CAP Operator:
### [Istio](https://istio.io/latest/docs/concepts/traffic-management/) (version >= 1.22)

Istio service mesh is used for HTTP traffic management. CAP Operator creates Istio resources to manage incoming HTTP requests to the application and to route requests on specific (tenant) subdomains.

> Determine the public ingress Gateway subdomain and the overall shoot domain for the system, and specify them in the [chart values](../helm/helm-values/). See [here](../helm/#installation) for an example.

> Note: Istio promoted many of its [APIs to v1 in the 1.22 release](https://istio.io/latest/blog/2024/v1-apis/). As of CAP Operator release v0.11.0, Istio version >= 1.22 is therefore a prerequisite.

### [sap-btp-service-operator](https://github.com/SAP/sap-btp-service-operator) or [cf-service-operator](https://sap.github.io/cf-service-operator/docs/)

These operators can be used for managing SAP BTP service instances and service bindings from within the Kubernetes cluster.

> If some SAP BTP services are not available for Kubernetes platforms, you can use [cf-service-operator](https://sap.github.io/cf-service-operator/), which creates the services for a Cloud Foundry space and inserts the required access credentials as Secrets into the Kubernetes cluster.

> Service credentials added as Kubernetes Secrets by these operators support additional metadata. If you don't use this feature, set `secretKey: credentials` in the spec to ensure that service credentials retain JSON data as-is. **We recommend using `secretKey` even when credential metadata is available, to reduce the overhead of parsing multiple JSON attributes.**

### ["Gardener" certificate management](https://github.com/gardener/cert-management)

This component is available in "Gardener" managed clusters and is used to manage TLS certificates and issuers. Alternatively, you can use [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager).
