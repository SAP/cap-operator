---
title: "Migrate to DomainRefs"
linkTitle: "Migrate to DomainRefs"
weight: 20
type: "docs"
description: >
  How to migrate existing CAP applications to use the new DomainRefs
---

As part of the enhanced domain management capabilities in the CAP Operator, the `domains` section in `CAPApplication` resources has been deprecated. It has been replaced by the more flexible and explicit `domainRefs`, which allows referencing one or more `Domain` or `ClusterDomain` resources.

This change give users full control over how CAP applications are exposed to external networks, including TLS handling, ingress routing, and DNS setup.

## Migration Support

- **Automatic Migration During CAP Operator Upgrade**

  When upgrading to a version [v0.15.0](https://github.com/SAP/cap-operator/releases/tag/v0.15.0) of the CAP Operator(that supports `domainRefs`), an automatic migration routine will run. This routine will:

  - Scan all existing `CAPApplication` resources in the cluster.

  - Delete all the existing network-related resources (Gateways, DNSEntries, Certificates) associated with the deprecated `domains`.

  - Generate the appropriate `Domain` or `ClusterDomain` resource with equivalent configuration.

  - Update the `CAPApplication` to use the new `domainRefs`.

- **Mutation Webhook**

  In addition to the upgrade routine, a mutation webhook is in place to handle any `CAPApplication` resources created or updated with the deprecated `domains` section. It performs the same transformation as the upgrade routine:

  - Converts the `domains` into a `Domain` or `ClusterDomain` resources.

  - Populate the new `domainRefs` accordingly.

  {{< alert color="warning" title="Warning" >}}
  The mutation webhook is triggered only during resource creation or update. Also, after the migration is complete and the `domains` section has been removed from your `CAPApplication` resources, the mutation webhook enforces the deprecation by preventing any further updates to the `domains`.

  Specifically:

  - If you reintroduce or modify the `domains` section in your Helm chart or manifest, the webhook will reject the change.

  - The webhook will return a clear error message instructing you to use the new `domainRefs` field instead.

  This validation ensures consistency across your deployments and encourages a complete move to the new domain model.
  {{< /alert >}}

## Post-Migration Steps

- **Verify Migrated Resources**

  After the upgrade, you can inspect your `CAPApplication` resources to confirm that the `domainRefs` has been added:

  ```bash
  kubectl get capapplication -n <your-app-namespace> <your-ca-name> -o yaml
  ```

  Check that:

  - The `domains` section has been removed.

  - One or more `domainRefs` entries exist.

  - Corresponding `Domain` or `ClusterDomain` resources are present.

- **Update Your Helm Charts**

  If you are using Helm charts to deploy your CAP applications, ensure that you update them to use the new `domainRefs` instead of the deprecated `domains`.

  Before:
  ```yaml
  spec:
    ...
    domains:
      istioIngressGatewayLabels:
        - name: app
          value: istio-ingressgateway
        - name: istio
          value: ingressgateway
      primary: cap-app-01.cluster.shoot.url.k8s.example.com
      secondary:
        - alt.shoot.example.com
    ...
  ```

  After:
  ```yaml
  spec:
    ...
    domainRefs:
    - kind: Domain
      name: cap-app-01-primary # <-- reference to Domain resource in the same namespace
    - kind: ClusterDomain
      name: common-secondary-domain # <-- reference to ClusterDomain resource in the cluster (either new or existing)
    ...
  ```
  Also, include the appropriate `Domain` or `ClusterDomain` resource templates in your Helm chart.
