---
title: "Documentation"
linkTitle: "Documentation"
weight: 10
menu:
  main:
    weight: 10
    pre: "<i class='fas fa-book pr-2'></i>"
---

[**CAP Operator**](https://github.com/sap/cap-operator) takes the complexity out of running [SAP Cloud Application Programming Model](https://cap.cloud.sap/docs) (CAP) applications on Kubernetes — so you ship features, not infrastructure.

Whether you're building a full SaaS platform with hundreds of tenants or a lean shared service with no tenant lifecycle at all, CAP Operator handles the heavy lifting:

- **Multi-tenant applications** — end-to-end SaaS lifecycle: onboarding, upgrades, deprovisioning, and everything in between, wired directly to SAP SaaS Provisioning service.
- **Services-only (tenant-agnostic) applications** — expose workloads publicly via named subdomains with zero tenant subscription overhead. Perfect for shared APIs and platform services.

---

**Deploy fast, deploy clean**
- One-command deployment of CAP servers, Approuters, and supporting workloads — networking included.
- Content deployers run as ordered Kubernetes jobs on every release, so your HTML5 apps and service configurations are always in sync.
- Services-only mode lets you go live without an Approuter or subscription flow, just clean subdomain-based exposure.

**Own your tenant lifecycle**
- Asynchronous tenant onboarding and offboarding, driven by SAP SaaS Provisioning service and executed as Kubernetes jobs.
- Automated tenant upgrades the moment a new version is ready — no manual rollouts.
- Fully sequenced operation pipelines with pre/post hooks and per-step failure control, so complex provisioning logic stays readable and reliable.
- Subscription dependency callbacks handled automatically, with per-service opt-in control.
- Pin individual tenants to a version when you need to — upgrade on your terms.

**Networking that just works**
- Automatic TLS certificate provisioning and DNS entry management, including customer-specific domains.
- Namespace-scoped and cluster-scoped domain resources — share a domain across applications or keep it isolated.
- Mutual TLS and Go-template-based custom DNS generation for advanced networking scenarios.

**Built for production operations**
- Credential rotation triggers automatic rolling restarts of only the affected workloads — everything else keeps running.
- Prometheus-driven cleanup automatically retires unused application versions, keeping your cluster lean.
- Version affinity *(experimental)*: users stay on the version they started with until their session ends, making zero-downtime upgrades a reality.
- Rich Prometheus metrics across the controller and subscription server — reconciliation errors, tenant operation durations, subscription request rates, and more.

---

The following diagram shows the major automation steps handled by CAP Operator during application deployment:

![workflow](/cap-operator/img/workflow.svg)

Explore the following sections to learn more.
