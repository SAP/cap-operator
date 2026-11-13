# CAP Operator integration tests (envtest)

This package contains integration ("e2e-like") tests for the CAP Operator. In contrast
to the unit tests under [`internal/controller`](../../internal/controller) — which use
fake clientsets — these tests run the **real controller** against a **real
kube-apiserver + etcd** started by [controller-runtime's
envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest), with the CAP
Operator CRDs and the required external CRDs installed.

## What it covers

| Test | Asserts |
|------|---------|
| `TestDomainReconciliation` | Given a `Domain` + a matching Istio ingress gateway, the controller adds its finalizer, resolves the ingress, sets a status state and creates the derived Istio `Gateway`. |
| `TestCAPApplicationReconciliation` | A `CAPApplication` with its BTP secrets gets a finalizer and is parked in `Processing` while waiting for a ready version. |
| `TestCAPApplicationMissingSecrets` | A `CAPApplication` without its BTP secrets never becomes `Consistent`. |
| `TestCAPApplicationVersionReconciliation` | The "dummy app" flow: the controller creates the owned workloads (CAP server + app-router `Deployment`s, content `Job`), parks the version in `Processing/WaitingForWorkloads`, and — once the dependency statuses are stubbed — advances the version to `Ready` and the application to provider-tenant provisioning. |
| `TestCAVResourceQuantityDriftAdmission` | **CEL admission** (real apiserver): a `CAPApplicationVersion` applied with an integer workload `resources.requests.cpu` (as `kubectl`/Helm sends it) is stored as an integer, so a typed full-object `Update` — which re-serializes the quantity to the string `"1"` — is rejected by the spec's `self == oldSelf` immutability rule, while a metadata-only patch is accepted. This reproduces the real bug the operator works around in [reconcile-capapplicationversion.go](../../internal/controller/reconcile-capapplicationversion.go). |
| `TestCAVSpecImmutabilityAdmission` | **CEL admission** (real apiserver): a change to the immutable `CAPApplicationVersion` spec is rejected on update. |

## CEL admission tests vs. the CEL unit tests

[pkg/apis/sme.sap.com/v1alpha2/cel_test.go](../../pkg/apis/sme.sap.com/v1alpha2/cel_test.go) validates the
`x-kubernetes-validations` rules in-process using the same validator libraries the
apiserver uses — fast, hermetic, and run by the default `go test ./...`. The admission
tests here **complement** (do not replace) them: they assert a few high-value rules —
especially the spec-immutability / transition rules — as the **real apiserver** applies
them across a create→update sequence, which the isolated validator only approximates.
Keep schema/required/enum coverage in the unit tests; only exercise behaviours whose
value comes from the real admission path here.


## What it does **not** cover

envtest starts **no kubelet, scheduler or controller-manager**, so:

- Workload pods never actually run. Tests stub `Deployment`/`Job` statuses (see
  `markDeploymentReady` / `markJobComplete` in [`harness_test.go`](harness_test.go)) to
  drive reconciliation forward.
- There is no garbage collector, so owner-reference cascade deletion does not happen.
- cert-manager / DNS controllers are absent, so TLS certificates never become `Ready`;
  a `Domain` therefore settles in `Processing`, not `Ready`.
- Full tenant provisioning and `CAPApplication` → `Consistent` require running
  app/router images, a database and XSUAA, and are out of scope here. Use a real
  cluster (e.g. [kind](https://kind.sigs.k8s.io/) with
  [kubernetes-sigs/e2e-framework](https://github.com/kubernetes-sigs/e2e-framework)) for
  that.

## Running

> **Platform note:** the envtest control-plane binaries (`kube-apiserver`, `etcd`) are
> published for **linux/amd64** and **darwin** only. On Windows, run the suite under WSL
> or in CI.

```bash
# from the repo root
make -C hack test-integration

# or manually
KUBEBUILDER_ASSETS="$(hack/bin/setup-envtest use 1.37.0 -p path)" \
    go test -tags integration ./test/integration/... -count=1 -v
```

The suite is gated behind the `integration` build tag, so the default `go build ./...`,
`go vet ./...` and `go test ./...` are unaffected.

## Configuration

The controller is configured for the smallest possible external-CRD surface
(see [`suite_test.go`](suite_test.go)):

- `CERT_MANAGER=cert-manager.io` — uses the small cert-manager `Certificate` CRD.
- `DNS_MANAGER=kubernetes` — native DNS, which needs no extra CRD or informer.

The required external CRDs are vendored as minimal, permissive (schema-less) definitions
under [`testdata/crd/external`](testdata/crd/external) so the suite is hermetic and
runs offline. Replace them with the upstream Istio / cert-manager CRDs if you want strict
schema validation.
