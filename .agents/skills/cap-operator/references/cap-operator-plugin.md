# CAP Operator Plugin

The [`@cap-js/cap-operator-plugin`](https://github.com/cap-js/cap-operator-plugin) is a CDS plugin that generates the Helm chart (and its supporting files) needed to deploy a multi-tenant CAP application with CAP Operator. Use it to scaffold the chart, generate runtime values, and build the final deployable chart.

Plugin docs: https://github.com/cap-js/cap-operator-plugin#readme

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

### Migrating deprecated fields

To migrate, upgrade the plugin and re-run:

```sh
cds add cap-operator --with-templates --force
```

`--force` overwrites the generated files. Review the diff (`git diff`) and selectively accept the plugin's changes while restoring any of your own customisations that were overwritten. Deploy only after the review is complete.

| Deprecated field | Deprecated since | Required plugin | Notes |
|---|---|---|---|
| `CAPApplication.spec.provider` (`subdomain`, `tenantId`) | CAP Operator v0.31.0 | v0.17.0+ | Removed from generated chart. Existing provider tenants must be **manually cleaned up** in the cluster. |
| `CAPApplication.spec.globalAccountId` | CAP Operator v0.28.0 | v0.15.0+ | Replaced by `providerSubaccountId`. |

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

**Required inputs:**

| Field | Description |
|---|---|
| `appName` | Lowercase alphanumeric + hyphens only (`^[a-z0-9-]+$`). Used as `xsappname` in saas-registry. |
| `capOperatorSubdomain` | Subdomain where CAP Operator is installed. Kyma default: `cap-op`. |
| `clusterDomain` | Shoot/cluster domain. Kyma: `kubectl get gateway -n kyma-system kyma-gateway -o jsonpath='{.spec.servers[0].hosts[0]}'` |
| `providerSubaccountId` | BTP provider subaccount ID. |

**Optional inputs:**

| Field | Description |
|---|---|
| `hanaInstanceId` | Required only when multiple HANA instances exist in the subaccount. |
| `imagePullSecret` | Kubernetes secret for private image registries. |

**Note:** `npx cap-op-plugin` requires `node_modules` to be present. If not already installed, run `npm install` first.

**Interactive mode** — prompts for each value:

```sh
npx cap-op-plugin generate-runtime-values
```

**File mode** — reads values from a YAML file:

```sh
npx cap-op-plugin generate-runtime-values --with-input-yaml <path-to-input.yaml>
```

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

> When using GitOps tools (e.g. Argo CD) that always render `Release.Revision` as `1`, set `app.version: "1.2.3"` in `runtime-values.yaml` to pin the `CAPApplicationVersion` version explicitly.

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

> **Environment variable consistency:** Helm does not merge arrays. If `values.yaml` defines env vars for a workload and `runtime-values.yaml` also defines env vars for the same workload, `runtime-values.yaml` must repeat all existing vars plus any new ones. The plugin copies existing env vars automatically when generating `runtime-values.yaml` via the CLI.
