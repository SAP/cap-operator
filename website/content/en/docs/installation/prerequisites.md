---
title: "Prerequisites"
linkTitle: "Prerequisites"
weight: 10
type: "docs"
description: >
  How to prepare the cluster before installing CAP Operator
---

It is recommended to use a [Gardener](https://gardener.cloud/) managed cluster for deploying CAP applications managed using the CAP Operator.

The Kubernetes cluster must be setup with the following prerequisites before installing the CAP Operator.

##### [Istio](https://istio.io/latest/docs/concepts/traffic-management/) (version >= 1.12)

Istio Service Mesh is used for HTTP traffic management. The CAP Operator creates Istio resources for managing incoming HTTP requests to the application as well as for routing requests on specific (tenant) subdomains.

> It is required to determine the public ingress gateway subdomain and the overall shoot domain for the system and specify them in the [Chart values](../../installation/helm-install/#values)

##### [cf-service-operator](https://sap.github.io/cf-service-operator/docs/) or [sap-btp-service-operator](https://github.com/SAP/sap-btp-service-operator)

These operators can be used for managing SAP BTP service instances and service bindings from within the Kubernetes cluster.

> Due to unavailability of certain BTP services for Kubernetes platforms, it is recommended to use the [cf-service-operator](https://github.com/sap/cf-service-operator/) which creates the services for a Cloud Foundry space and injects the required access credentials as secrets into the Kubernetes cluster.

> Please note that service credentials added as Kubernetes Secrets to a namespace, by these operators, supports additional metadata. If you do not use this feature of these operators, it is also required that you use `secretKey: credentials` in the spec of these operators to ensure the service credentials retain any JSON data as it is. **It is recommended to use `secretKey`, even when credential metadata is available to reduce the overhead of interpreting parsing multiple JSON attributes.**

##### [SAP Gardener Certificate Management](https://github.com/gardener/cert-management)

This component is available in clusters managed by SAP Gardener and will be used to manage TLS Certificates and issuers. SAP Gardener manages encryption, issuing and signing of certificates. Alternatively, [cert-manager.io cert-manager](https://github.com/cert-manager/cert-manager) can be used.
