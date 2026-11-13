# CAP Operator
Guidelines for AI coding agents

## Overview

**CAP Operator** manages the lifecycle of multi-tenant [SAP Cloud Application Programming Model](https://cap.cloud.sap/docs) (CAP) applications on Kubernetes. It takes the complexity out of running CAP apps — so you ship features, not infrastructure.

Key capabilities:
- **Multi-tenant SaaS lifecycle** — end-to-end onboarding, upgrades, and deprovisioning wired directly to SAP SaaS Provisioning service via asynchronous Kubernetes jobs.
- **Services-only (tenant-agnostic) mode** — expose workloads on named subdomains without tenant subscription overhead.
- **Networking** — automatic TLS certificate provisioning, DNS management, and Istio `VirtualService` routing per tenant/subdomain, including customer-specific domains.
- **Production operations** — credential rotation triggers rolling restarts of affected workloads; Prometheus-driven cleanup retires unused application versions.

Full documentation: https://sap.github.io/cap-operator/docs/

## Install / Deploy

### Prerequisites

* K8s, preferably project "Gardener" cluster

### Deploy

Create a namespace and install via Helm, providing the subscription server `domain` and `dnsTarget` for your cluster:

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator \
  oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator \
  --set subscriptionServer.domain=cap-operator.<CLUSTER-DOMAIN> \
  --set subscriptionServer.dnsTarget=public-ingress.<CLUSTER-DOMAIN>
```

Alternatively, use a values file:

```yaml
# my-cap-operator-values.yaml
subscriptionServer:
  dnsTarget: public-ingress.<CLUSTER-DOMAIN>
  domain: cap-operator.<CLUSTER-DOMAIN>
```

```bash
kubectl create namespace cap-operator-system
helm upgrade -i -n cap-operator-system cap-operator \
  oci://ghcr.io/sap/cap-operator-lifecycle/helm/cap-operator \
  -f my-cap-operator-values.yaml
```

See the [Helm installation guide](https://sap.github.io/cap-operator/docs/installation/helm/) for full chart values reference.


## Project Structure

```
cap-operator/
├── cmd/
│   ├── controller/         # Entry point for the controller binary
│   ├── server/             # Entry point for the subscription server binary
│   │   └── internal/       # JWT validation, certificate checks, HTTP handlers
│   └── web-hooks/          # Entry point for the admission webhook binary
│       └── internal/       # Webhook request handlers
├── internal/
│   ├── controller/         # Core reconciliation logic for all custom resources
│   └── util/               # Shared utilities: logging, config, UAA, VCAP credentials
├── pkg/
│   ├── apis/
│   │   └── sme.sap.com/
│   │       ├── v1alpha1/   # Previous API version (deprecated)
│   │       └── v1alpha2/   # Current API version — type definitions live here
│   └── client/             # Generated client, informers, listers, and apply configs
├── crds/                   # Generated CRD YAML manifests (do not edit manually)
├── build/                  # Dockerfiles for controller, server, and web-hooks images
├── hack/                   # Developer tooling: Makefile, code generation scripts
└── website/                # Hugo documentation site (source for sap.github.io/cap-operator)
```

Key relationships:
- Edit types in `pkg/apis/sme.sap.com/v1alpha2/` → regenerate `pkg/client/` and `crds/` via `make -C hack types` and `make -C hack manifests`.
- Reconciliation logic for each custom resource lives in `internal/controller/reconcile-<resource>.go`.
- The three binaries (`controller`, `server`, `web-hooks`) are built from their respective `cmd/` entry points and packaged with the Dockerfiles in `build/`.

## Testing

To run the unit and integration tests, run the following command:

```bash
make -C hack test
make -C hack test-integration
```

## Development Conventions

### Guidelines for Programming Assistance

When assisting with programming tasks, adhere to the following principles:

* **Follow Requirements**: Carefully follow the user's requirements to the letter.
* **Plan First**: For any non-trivial change, first describe a detailed, step-by-step plan, including the files you intend to modify and the tests you will add or update.
* **Test Thoroughly**: Implement comprehensive tests to ensure correctness and prevent regressions.
* **Comment Intelligently**: Add comments to explain the "why" behind complex or non-obvious code, keeping in mind that the reader may not be a Kubernetes expert.
* **No TODOs**: Leave no `TODO` comments, placeholders, or incomplete implementations.
* **Prioritize Correctness**: Always prioritize security, scalability, and maintainability in your implementations.

### Avoiding Loops

When performing complex tasks, especially those involving code modifications and verification, it's important to avoid getting into loops. A loop can occur when the agent repeatedly tries the same action without success, or when it gets stuck in a cycle of analysis, action, and failure.

To avoid loops:
* **Analyze the problem carefully**: Before taking any action, make sure you understand the problem and have a clear plan to solve it.
* **Break down the problem**: Decompose complex problems into smaller, more manageable steps.
* **Verify each step**: After each step, verify that it was successful before moving on.
* **Don't repeat failed actions**: If an action fails, diagnose the root cause and try a different approach.
* **Ask for help**: If stuck, ask the user for clarification.

### Code Style

The project follows the standard Go code style and partly the official [Kubernetes coding conventions](https://www.k8s.dev/docs/guide/coding-convention/). All code must be formatted with `gofmt` and vetted with `go vet`:

```bash
gofmt -l -s -w ./
go vet ./...
```

Every new source file must include the SPDX license header:

```go
/*
SPDX-FileCopyrightText: <year> SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
```

### Code Generation

Do not manually edit generated files. After modifying API type definitions in `pkg/apis/`, regenerate the affected artefacts from the repository root:

| Command | What it generates |
|---|---|
| `make -C hack types` | Deep-copy functions, typed client, informers, and listers under `pkg/client/` |
| `make -C hack manifests` | CRD YAML files under `crds/` |

### Testing

Unit tests live alongside the code they test in `_test.go` files. The controller tests use an in-memory fake Kubernetes client — no live cluster is required.

Run all tests:

```bash
go test ./...
```

Run tests for a specific package:

```bash
go test ./internal/controller/...
```

### Test Coverage

Target **85% coverage on new code**. To measure:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Coverage is a floor, not a goal. A test that simply executes a code path without asserting anything meaningful does not count. Prioritize tests that:

* **Cover real logic** — decision branches, state transitions, reconciliation outcomes.
* **Test edge cases** — empty inputs, missing fields, resources in unexpected states, concurrent updates.
* **Test boundary conditions** — version comparisons, quota limits, timeout thresholds, first/last elements in lists.
* **Verify error paths** — invalid configurations, API call failures, missing secrets, conflicting resources.

What to avoid:
* Tests that only assert the happy path and ignore error returns.
* Tests that mirror the implementation so closely they break on every refactor without catching bugs.
* Achieving the coverage target by testing trivial getters or generated code — focus on `internal/controller/` and `cmd/*/internal/` where the real complexity lives.

### Security

When generating or reviewing code, flag any obvious security issues before presenting the result. List each finding as a bullet with a sub-bullet describing the recommended remediation.

### Documentation

Any new or changed functionality must be accompanied by a corresponding documentation update under `website/content/en/docs/`. The website is the published user-facing documentation at https://sap.github.io/cap-operator/docs/ — treat it as part of the deliverable, not an afterthought.

Documentation to update depending on the type of change:

* **New or changed custom resource fields** — update the relevant resource reference page under `website/content/en/docs/usage/resources/`.
  * Add or update the field description, valid values, and a YAML example showing the field in context.

* **New operator behaviour or usage pattern** — add or update a page under `website/content/en/docs/usage/`.
  * Describe what the feature does, when to use it, and include a minimal working example.

* **New or changed controller configuration** (environment variables) — update `website/content/en/docs/configuration/_index.md`.
  * Document the variable name, accepted values, default, and effect.

* **New installation prerequisite or changed Helm values** — update `website/content/en/docs/installation/`.
  * Reflect any new required steps or changed chart values in the relevant page.

* **Important features, Breaking changes or deprecations** — add an entry to `website/content/en/docs/whats-new.md`.
  * State the feature, what changed, what the migration path is, and which version introduced the change.

### Dependencies

The project uses Go modules. To add a new dependency, import it in the code and run:

```bash
go mod tidy
```

### Commits

The project follows the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`.

Examples:
```
feat(controller): add version affinity support
fix(domain): correct DNS entry reconciliation for wildcard mode
chore: update Go dependencies
```

### Contributions

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/SAP/cap-operator/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).
