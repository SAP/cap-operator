# CAP Operator Plugin

The [`@cap-js/cap-operator-plugin`](https://github.com/cap-js/cap-operator-plugin) is a CDS plugin that generates the Helm chart (and its supporting files) needed to deploy a multi-tenant CAP application with CAP Operator. Use it to scaffold the chart, generate runtime values, and build the final deployable chart.

Plugin docs: https://github.com/cap-js/cap-operator-plugin#readme

---

## Workflow

**Do not run any of these steps on skill invocation.** Start this workflow only when the user explicitly asks to generate a Helm chart or deploy the app. Once asked, chart generation and deployment are two separate phases — finish the first and let the user decide before starting the second; they're often only after the chart.

**1. Generate the Helm chart.** First determine whether the app is multitenant or service-only by checking for a populated MTX sidecar folder (`mtx/sidecar` with contents):

- **Sidecar present** → multitenant app → `cds add cap-operator --with-templates`
- **No sidecar** → tenant-independent app → `cds add cap-operator --with-service-only`

Run the install and the appropriate command right away. Chart generation reads no environment values, so there's nothing to ask up front — skip the questions about namespace, image registry, or BTP services. Say which variant you picked and why, rather than offering a menu.

Reach for `--with-configurable-templates` instead of `--with-templates` only when the request clearly needs Helm template functions (`if`, `range`, custom helpers) inside CAP Operator resources.

**2. Ask whether they want to deploy.** This is the gate between the two phases. If they only wanted the chart, you're done — leave `runtime-values.yaml` alone. Hold off on everything that feeds it (gathering values, running `kubectl`, building an input file) until the answer is yes.

**3. After a yes, generate `runtime-values.yaml`.** Collect the required inputs first: `appName`, `capOperatorSubdomain`, `clusterDomain`, and `providerSubaccountId`. Ask for any value you don't have — placeholders like `<YOUR_CLUSTER_DOMAIN>` and files with missing values are worse than a question.

For `clusterDomain`, derive it from the current kube context (see below), then ask the user to confirm the derived value. Fall back to free-text entry only if derivation fails.

---

## Installing the Plugin

```sh
npm add @cap-js/cap-operator-plugin -D
```

**Requirements:** `@sap/cds >= 9`, `@sap/cds-dk >= 9`, `@sap/cds-foss >= 5`.

---

## Generating the Helm Chart

```sh
cds add cap-operator --with-templates
# or, when Helm template functions are needed inside CAP Operator resources:
cds add cap-operator --with-configurable-templates
```

This creates a `chart/` folder including a `chart/templates/` folder — the chart is deployment-ready without any further build step.

> The chart is now complete. Ask whether the user wants to deploy before doing anything toward `runtime-values.yaml` — see "Workflow" above.

### `--with-templates` (default choice)

```sh
cds add cap-operator --with-templates
```

Creates `chart/Chart.yaml`, `chart/values.yaml`, `chart/values.schema.json`, and a `chart/templates/` folder. The templates can be edited directly when more complex scenarios require it.

What lands in `chart/templates/`:
- `service-binding.yaml` / `service-instance.yaml` — static BTP service operator templates
- `_helpers.tpl` — generated helpers (adjusts for xsuaa vs IAS)
- `domain.yaml` — a `sme.sap.com/v1alpha1` `Domain` resource
- `cap-operator-cros.yaml` — the `CAPApplication` + `CAPApplicationVersion` template, using `range` over `values.workloads`

### `--with-configurable-templates`

```sh
cds add cap-operator --with-configurable-templates
```

Produces a chart where all CAP Operator resource configuration lives in `templates/cap-operator-cros.yaml` rather than in `values.yaml`. Workload images are the only workload-related values kept in `values.yaml`. This unlocks full Helm template functions (`if`, `range`, custom helpers) inside CAP Operator resources.

Key differences from `--with-templates`:
- `cap-operator-cros.yaml` is the expanded/explicit variant — each workload type (server, app-router, tenant-job, content-deploy, ams-deployer) is written out individually with Helm conditionals.
- `values.yaml` contains only workload image references; ports, env, `tenantOperations`, `contentJobs`, and `serviceExposures` live in `templates/cap-operator-cros.yaml`.
- `Chart.yaml` carries the annotation `app.kubernetes.io/part-of: cap-operator-configurable-templates`.

The two flags are mutually exclusive.

### `--with-service-only`

```sh
cds add cap-operator --with-service-only
```

For tenant-independent ("service-only") applications. Adds only service-related configurations — no tenant provisioning, no saas-registry wiring. See [service-only workloads](https://sap.github.io/cap-operator/docs/usage/services-workload/).

### Detecting the chart variant

When working with an existing chart, read `chart/Chart.yaml` annotations to determine the variant:

| Annotation | Value | Variant |
|---|---|---|
| `app.kubernetes.io/part-of` | `cap-operator-configurable-templates` | `--with-configurable-templates` |
| `app.kubernetes.io/component` | `service-only` | `--with-service-only` |
| *(neither)* | — | `--with-templates` |

### Where to edit workload configuration

| What to change | `--with-templates` | `--with-configurable-templates` |
|---|---|---|
| Workload images | `chart/values.yaml` | `chart/values.yaml` |
| Env vars, ports, resource limits | `chart/values.yaml` | `chart/templates/cap-operator-cros.yaml` |
| `tenantOperations`, `contentJobs`, `serviceExposures` | `chart/values.yaml` | `chart/templates/cap-operator-cros.yaml` |
| Service instances / bindings | `chart/values.yaml` | `chart/values.yaml` |

### Validating the chart

```sh
helm lint chart/
```

Validation errors for runtime values (fields populated by `runtime-values.yaml`) can be ignored at this stage.

### Converting an existing chart

If you already have a basic chart and want to switch to configurable templates:

```sh
npx cap-op-plugin convert-to-configurable-template-chart
# also migrate runtime-values.yaml:
npx cap-op-plugin convert-to-configurable-template-chart --with-runtime-yaml chart/runtime-values.yaml
```

---

## Generating `runtime-values.yaml`

`values.yaml` holds design-time (repo-committable) values. Environment-specific ("runtime") values are kept in `chart/runtime-values.yaml`, which **must not** be committed.

> **Prerequisite:** Generate `runtime-values.yaml` only once the user has chosen to deploy and all required inputs below are known. Ask for any missing value rather than filling in a placeholder or guess.

**Required inputs:**

| Field | Description |
|---|---|
| `appName` | Lowercase alphanumeric + hyphens only (`^[a-z0-9-]+$`). Used as `xsappname` in saas-registry. |
| `capOperatorSubdomain` | Subdomain where CAP Operator is installed. On a **Kyma** cluster, recommend the default `cap-op` instead of asking. |
| `clusterDomain` | Shoot/cluster domain. See "Deriving the cluster domain" below. |
| `providerSubaccountId` | BTP provider subaccount ID. |

### Deriving the cluster domain

Prefer deriving `clusterDomain` from the cluster over manual entry. Read it from the active kube context, then ask the user to confirm the derived value. Ask the user to type the domain only if derivation fails.

```sh
kubectl config view --minify --output jsonpath={.clusters[*].cluster.server}
```

This returns the API server URL; derive the cluster/shoot domain from it. On Kyma the primary domain can alternatively be read from the ingress gateway:

```sh
kubectl get gateway -n kyma-system kyma-gateway -o jsonpath='{.spec.servers[0].hosts[0]}'
```

**Optional inputs:**

| Field | Description |
|---|---|
| `hanaInstanceId` | Required only when multiple HANA instances exist in the subaccount. |
| `imagePullSecret` | Kubernetes secret for private image registries. |

**Always use file mode** — reads values from a YAML file:

```sh
npx cap-op-plugin generate-runtime-values --with-input-yaml <path-to-input.yaml>
```

> The bare `npx cap-op-plugin generate-runtime-values` runs an interactive `enquirer` prompt that **cannot be driven by piped input** (it throws `ERR_USE_AFTER_CLOSE`). An agent must always pass `--with-input-yaml` with a fully populated file.

Sample input file:

```yaml
appName: incidentapp
capOperatorSubdomain: cap-op
clusterDomain: abc.com
providerSubaccountId: da37c8e0-74d4-abcd-b5e2-sd8f7d8f7d8f
hanaInstanceId: 46e285d9-abcd-4c7d-8ebb-502sd8f7d8f7d
imagePullSecret: regcred
```

What gets written to `chart/runtime-values.yaml`:
- `serviceInstances` parameters — saas-registry/subscription-manager callback URLs (`capOperatorSubdomain.clusterDomain`), xsuaa/identity `xsappname`
- `serviceBindings` (IAS only)
- `app.domains.primary: <appName>.<clusterDomain>`
- `app.istioIngressGatewayLabels`
- `btp.providerSubaccountId`
- `imagePullSecrets` (omitted if not provided)
- For basic charts: `CDS_CONFIG` env var (with `database_id`) merged into relevant workloads
- For configurable-template charts: `hanaInstanceId` as a top-level value

---

## Deploying

If `values.yaml` includes an `xsuaa` service instance (the common case), use `--set-file` to pass `xs-security.json` as `jsonParameters`:

```sh
helm upgrade -i -n <namespace> <release-name> <project-path>/chart \
  --set-file serviceInstances.xsuaa.jsonParameters=<project-path>/xs-security.json \
  -f <project-path>/chart/runtime-values.yaml
```

If there is no xsuaa service instance:

```sh
helm upgrade -i -n <namespace> <release-name> <project-path>/chart \
  -f <project-path>/chart/runtime-values.yaml
```
