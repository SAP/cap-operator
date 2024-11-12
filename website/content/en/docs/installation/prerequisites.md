---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  How to prepare the cluster before installing CAP Operator
---

We recommend that you use a "[Gardener](https://gardener.cloud/)" managed cluster to deploy CAP applications that are managed with CAP Operator.

The Kubernetes cluster must be set up with the following prerequisites before you install CAP Operator:
##### [Istio](https://istio.io/latest/docs/concepts/traffic-management/) (version >= 1.22)

Istio service mesh is used for HTTP traffic management. CAP Operator creates Istio resources to manage incoming HTTP requests to the application as well as to route requests on specific (tenant) subdomains.

> It's required that you determine the public ingress Gateway subdomain and the overall shoot domain for the system and specify them in the [chart values](../../installation/helm-install/#values)

> Note: Istio promoted many of its [APIs to v1 in 1.22 release](https://istio.io/latest/blog/2024/v1-apis/). Hence as of CAP Operator release v0.11.0 istio version >= 1.22 is a prerequisite.

##### [sap-btp-service-operator](https://github.com/SAP/sap-btp-service-operator) or [cf-service-operator](https://sap.github.io/cf-service-operator/docs/)

These operators can be used for managing SAP BTP service instances and service bindings from within the Kubernetes cluster.

> If some SAP BTP services are not available for Kubernetes platforms, you may use [cf-service-operator](https://sap.github.io/cf-service-operator/), which creates the services for a Cloud Foundry space and inserts the required access credentials as Secrets into the Kubernetes cluster.

> Please note that service credentials added as Kubernetes Secrets to a namespace by these operators, support additional metadata. If you don't use this feature of these operators, use `secretKey: credentials` in the spec of these operators to ensure that the service credentials retain any JSON data as it is. **We recommend that you use `secretKey`, even when credential metadata is available to reduce the overhead of interpreting parsing multiple JSON attributes.**

##### ["Gardener" certificate management](https://github.com/gardener/cert-management)

This component is available in clusters managed by "Gardener" and will be used to manage TLS certificates and issuers. "Gardener" manages encryption, issuing, and signing of certificates. Alternatively, you can use [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager).