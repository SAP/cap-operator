---
workspace: ../../..
planning:
  model: hai-claude/anthropic--claude-4.7-opus
  reviewer_model: hai-gemini/gemini-2.5-pro
  max_rounds: 3
  timeout: 30m
  image: alpine
execution:
  model: hai-claude/anthropic--claude-4.6-sonnet
  timeout: 8m
  concurrency: 3
  image: go-alpine
correction:
  max_retries: 2
  max_waves: 2
acceptance:
  model: hai-claude/anthropic--claude-4.7-opus
  image: go-alpine
  timeout: 15m
---

# Allow CAPApplicationVersion Cleanup Without a Prometheus Connection

The CAP Operator controller currently refuses to start the `CAPApplicationVersion`
cleanup routines unless the `PROMETHEUS_ADDRESS` environment variable is set
*and* a Prometheus client can be initialised against it (a `Runtimeinfo` probe
must succeed). This makes Prometheus a hard dependency for an entirely
metrics-free use case: an application whose `CAPApplicationVersion` workloads
declare no `monitoring.deletionRules` would still like older, unused versions
to be cleaned up automatically once a newer version becomes `Ready`.

This change decouples the cleanup loop from Prometheus availability:

- The cleanup routines start unconditionally.
- Versions whose deployment workloads declare *no* deletion rules continue to
  be eligible for cleanup as today, regardless of whether Prometheus is
  reachable.
- Versions that *do* declare deletion rules are only evaluated when a working
  Prometheus client is available; otherwise they are skipped (left for the
  next cycle) with a clear log message and *not* deleted.

The annotation contract on `CAPApplication` (`sme.sap.com/enable-cleanup-monitoring`)
is unchanged. Defaulting that annotation, or adding an opt-out value, is
explicitly out of scope here and tracked separately.

## Background — current behaviour

All paths below are inside the controller package and refer to the existing
implementation that this change is modifying.

`internal/controller/version-monitoring.go`:

- `parseMonitoringEnv()` returns `nil` when `PROMETHEUS_ADDRESS` is empty or
  whitespace.
- `(*Controller).startVersionCleanup(ctx)` short-circuits with `return` when
  `parseMonitoringEnv()` returned `nil`. The schedule and worker goroutines
  are never started.
- `initializeVersionCleanupOrchestrator(ctx, mEnv)` constructs a Prometheus
  client and validates it with `v1api.Runtimeinfo(ctx)`. Either failure
  returns `nil`, and the surrounding loop in `startVersionCleanup` retries
  after `acquireClientRetryDelay` (default `1h`).
- The `cleanupOrchestrator` struct stores the `promv1.API` once at startup;
  the `api` value is then read by every downstream evaluator and is assumed
  to be non-nil.
- `evaluateWorkloadForCleanup(ctx, cav, wl, promapi)` is the per-workload
  evaluator. When `wl.DeploymentDefinition.Monitoring == nil` *or*
  `Monitoring.DeletionRules == nil`, the workload is auto-eligible without
  ever touching the Prometheus client; otherwise it calls
  `evaluateExpression` or `evaluateMetric`, both of which dereference the
  `promv1.API`.

`internal/controller/controller.go` (around line 233):

- Calls `c.startVersionCleanup(qCxt)` from the controller's main goroutine
  group, wrapped in `wg.Go(...)`.

`internal/controller/reconcile.go` (line 57):

- Defines `AnnotationEnableCleanupMonitoring = "sme.sap.com/enable-cleanup-monitoring"`.
- `queueVersionsForCleanupEvaluation` already filters CAPApplications by this
  annotation (only `"true"` and `"dry-run"` enable the loop) and excludes
  versions linked to tenants and versions newer than the latest `Ready`
  version. None of that filtering needs to change.

Documentation that mentions the old behaviour:

- `website/content/en/docs/usage/version-monitoring.md` — section
  "Integration with Prometheus" claims "If no Prometheus address is supplied,
  the version monitoring function is not started."
- `website/content/en/docs/configuration/_index.md` — the `PROMETHEUS_ADDRESS`
  bullet says "If not set, the version monitoring function is not started."

Tests in `internal/controller/version-monitoring_test.go` that hard-code the
"empty address ⇒ nil monitoring env / no routines" assumption:

- `TestMonitoringEnv` — first sub-case asserts `mEnv == nil` when the env var
  is unset.
- `TestGracefulShutdownMonitoringRoutines` — sets `PROMETHEUS_ADDRESS` before
  starting the cleanup loop.
- `Test_initializeVersionCleanupOrchestrator` — passes a non-empty address.

## Required behaviour

### Routine startup

`startVersionCleanup(ctx)` must always start the schedule and worker
goroutines, regardless of `PROMETHEUS_ADDRESS`:

- `parseMonitoringEnv()` must always return a non-nil `*monitoringEnv`.
  - When `PROMETHEUS_ADDRESS` is unset/blank, `address` is the empty string.
    The other fields (`acquireClientRetryDelay`, `evaluationInterval`) are
    populated using the same env-var lookup with the same defaults
    (`1h` and `10m`) as today.
  - When `PROMETHEUS_ADDRESS` is set, behaviour is unchanged.
- `startVersionCleanup` must no longer `return` early based on the
  monitoring env. The schedule + worker goroutines must run for the lifetime
  of `ctx`, with the same panic-recovery + `restartSignal` semantics as
  today.
- The Prometheus *client* must no longer block routine startup. The current
  `setup()` retry loop (which sleeps `acquireClientRetryDelay` while the
  Prom server is unavailable) must not be on the critical path for starting
  the worker. The orchestrator must be constructable without a working
  Prometheus connection.

### Prometheus client lifecycle

Introduce a way to obtain the current Prometheus API client lazily, so that
each evaluation cycle reflects the latest reachability:

- When `address` is empty, the provider always reports "unavailable"; no
  client is ever constructed and no `Runtimeinfo` probe is made.
- When `address` is non-empty:
  - A client is constructed; if construction fails, the provider reports
    "unavailable" for this cycle and logs the error at most once per
    transition from available → unavailable (avoid log spam every cycle).
  - The client's reachability is verified via `Runtimeinfo` at most once per
    `acquireClientRetryDelay` while it is unavailable, *not* on every
    queueing iteration. Once a probe succeeds, the working client is cached
    and reused; subsequent query failures during evaluation do not by
    themselves invalidate the cache (those are already handled per-query
    today).
  - On a successful probe transitioning from unavailable → available, log
    an informational message.

Implementation freedom: this can be a `promClientProvider` interface, a
field on `cleanupOrchestrator` mutated under a mutex, or any equivalent
design. The only external contract is "give me the current API or tell me
it's unavailable, without doing a network call on every evaluation".

### Per-version evaluation

`evaluateVersionForCleanup` and `evaluateWorkloadForCleanup` must accept the
case where the Prometheus API is currently unavailable:

- For each deployment workload of the version:
  - Workloads whose `deploymentDefinition.monitoring` is nil, or whose
    `deploymentDefinition.monitoring.deletionRules` is nil, remain
    auto-eligible. No Prometheus access is required or attempted.
  - Workloads with non-nil `deletionRules`:
    - If the Prometheus API is available: evaluate as today (expression or
      metric rules) and use the result.
    - If the Prometheus API is unavailable: the workload is *not* eligible
      for cleanup. Log a single informational/warning entry per evaluation
      attempt naming the version, the workload, and the reason
      ("prometheus client unavailable"). Do not return an error from
      `evaluateVersionForCleanup`; the version simply stays in the system
      and will be re-considered on the next cycle.
- The "all deployment workloads must be eligible for the version to be
  cleaned up" rule is unchanged.
- The annotation-controlled deletion vs. dry-run decision in
  `evaluateVersionForCleanup` (`AnnotationEnableCleanupMonitoring == "true"`
  ⇒ delete; `"dry-run"` ⇒ event only) is unchanged.

In particular, this means a `CAPApplicationVersion` whose deployment
workloads collectively declare *no* deletion rules can be cleaned up even
when no Prometheus is configured — that is the central use case being
unlocked.

### Queue behaviour

`queueVersionsForCleanupEvaluation` continues to:

- Only consider `CAPApplication`s whose
  `sme.sap.com/enable-cleanup-monitoring` annotation is `"true"` or
  `"dry-run"` (case-insensitive).
- Exclude versions tied to tenants (`spec.version` or
  `status.currentCAPApplicationVersionInstance`).
- Exclude versions whose `spec.version` is greater than the latest `Ready`
  version (semver compare).
- Skip everything when no `Ready` version exists.

These rules must still apply regardless of Prometheus availability.

### Logging / observability

- A clear `klog.InfoS` (or `klog.WarningS`) line when the cleanup loop is
  starting without a configured Prometheus address, e.g.
  "PROMETHEUS_ADDRESS is not set; only versions without deletion rules will
  be cleaned up".
- A clear log line when a workload is skipped because the Prom client is
  unavailable (one per workload per evaluation cycle is fine; do not flood
  the log every queue iteration).
- Existing per-query error logs in `executePromQL`, `evaluateExpression`,
  and `evaluateMetric` are kept.

### Documentation updates

`website/content/en/docs/usage/version-monitoring.md`:

- The "Integration with Prometheus" paragraph must be rewritten to say:
  Prometheus is only required to evaluate workloads with `deletionRules`.
  When `PROMETHEUS_ADDRESS` is not set (or the configured server is
  unreachable), the cleanup loop still runs; versions whose deployment
  workloads have no `deletionRules` can be cleaned up, and versions with
  `deletionRules` are skipped until Prometheus becomes available again.
- The "Evaluating CAPApplicationVersion Resources for Cleanup" section
  must mention the same Prometheus-availability behaviour next to the
  existing description of how workloads without `deletionRules` are
  treated.

`website/content/en/docs/configuration/_index.md`:

- Update the `PROMETHEUS_ADDRESS` bullet to: "URL of the Prometheus server
  for executing PromQL queries... If not set, the controller still runs
  the version cleanup loop, but only versions whose workloads have no
  `deletionRules` are eligible for cleanup."

## Constraints

- Go only; no new third-party dependencies. Reuse the existing
  `github.com/prometheus/client_golang/api` package already in use.
- Public API of the `internal/controller` package (types and functions
  exported from the package) must not be broken. Keep
  `cleanupOrchestrator`, `monitoringEnv`, `initializeVersionCleanupOrchestrator`,
  `startVersionCleanup`, `queueVersionsForCleanupEvaluation`,
  `processVersionCleanupQueue`, and `processVersionCleanupQueueItem`
  callable with their current signatures from tests, even if their
  internals change. The `cleanupOrchestrator.api` field may be replaced
  by an alternative client-provider field if you also update the tests
  that touch it.
- The controller CRDs, generated client code under `pkg/client/...`, and
  the API types in `pkg/apis/sme.sap.com/v1alpha1` must not change.
- The `sme.sap.com/enable-cleanup-monitoring` annotation contract is
  unchanged. Do not introduce a new default, do not introduce new
  accepted values, do not invert any condition.
- The Prometheus reachability probe must remain rate-limited. Do not call
  `Runtimeinfo` (or any equivalent) on every iteration of the schedule
  loop — at most once per `acquireClientRetryDelay`.
- Existing tests must continue to pass after their assertions about the
  "empty address ⇒ nil mEnv / no routines" behaviour are updated to
  reflect the new contract. No tests may be deleted; they are migrated.

## Non-goals

- Defaulting the `sme.sap.com/enable-cleanup-monitoring` annotation to
  `"true"` or introducing an explicit opt-out value (e.g. `"false"`,
  `"disabled"`). This is tracked separately and is out of scope here.
- Changing how individual PromQL queries are constructed or what
  `Gauge`/`Counter`/`Expression` evaluation means.
- Changing how `ServiceMonitor` resources are created from
  `monitoring.scrapeConfig`.
- Adding a Prometheus-availability indicator to any CR status field.
- Changing the controller's leader election, queue, or reconcile
  scheduler behaviour for any other resource.

## Tests

All tests live in `internal/controller/version-monitoring_test.go` (plus
`testdata/version-monitoring/*.yaml`). The build/test commands the
planner should attach to validation tasks are:

- `go build ./...`
- `go test ./internal/controller/...`
- `go test ./...` for a final wide check.

Update existing tests as follows; they must keep passing.

- `TestMonitoringEnv`:
  - The case where `PROMETHEUS_ADDRESS` is unset must now assert that
    `parseMonitoringEnv()` returns a non-nil `*monitoringEnv` whose
    `address` is empty and whose `acquireClientRetryDelay` /
    `evaluationInterval` carry their defaults (`1h`, `10m`). The cases
    that set the address remain as today.
- `TestGracefulShutdownMonitoringRoutines`:
  - Must additionally cover the case where `PROMETHEUS_ADDRESS` is *not*
    set. `startVersionCleanup` must still launch the routines and they
    must shut down cleanly when the context is cancelled.
- `Test_initializeVersionCleanupOrchestrator`:
  - The "server unavailable" case must no longer rely on the orchestrator
    being `nil`. The orchestrator must be constructable; the assertion
    becomes "the embedded Prometheus client provider reports unavailable"
    rather than "initialiser returned nil". If the test currently waits
    for a context deadline as a proxy for "kept retrying", replace that
    with a direct assertion against the provider.
  - Add an explicit case: empty address ⇒ orchestrator constructs;
    provider is permanently unavailable; no HTTP calls are made (the
    test's mock server should record zero `runtimeinfo` hits).

Add new test coverage:

- A version-cleanup evaluation test where Prometheus is *not* configured
  (empty address) and a CAV's deployment workloads all have no
  `deletionRules`: the evaluator must mark the version eligible and the
  CAV must be deleted (when the CAPApplication annotation is `"true"`).
  Reuse the existing `setupTestControllerWithInitialResources` helper
  and add a `cav-no-deletion-rules.yaml` (or equivalent) fixture under
  `testdata/version-monitoring/`.
- A version-cleanup evaluation test where Prometheus is *not* configured
  but the CAV has at least one workload with `deletionRules`: the
  evaluator must *not* delete the CAV, must not panic, and must not
  return an error that causes the queue to spin (no requeues for the
  same item beyond the normal flow). The existing
  `cav-v1-deletion-rules.yaml` fixture is suitable.
- A version-cleanup evaluation test where the address *is* configured
  but the mock Prom server returns 503 from `runtimeinfo`: a CAV with
  `deletionRules` is not deleted; a CAV with no `deletionRules` (in the
  same evaluation cycle, separate fixture) *is* deleted.
- A test that the reachability probe is rate-limited: drive two
  consecutive evaluation cycles closer together than
  `acquireClientRetryDelay` and assert the mock Prom server records at
  most one `runtimeinfo` request across both. Use a short
  `acquireClientRetryDelay` plus a shorter test-window between cycles
  to make this deterministic without `time.Sleep` blocking the test.

`TestVersionSelectionForCleanup` and `TestVersionCleanupEvaluation`
existing scenarios should continue to pass unchanged once the production
code is updated. If the orchestrator's `api` field is renamed or
replaced, update the tests' construction of `cleanupOrchestrator` to
match — keep the same scenarios.

## Acceptance

The acceptor will run the merged code in the `go-alpine` image and verify
each of the following criteria. Any single failing criterion produces a
rejection naming that criterion, so the re-planner can target the gap.

1. **Build is green.** `go build ./...` exits 0 from the repo root.
2. **Full test suite is green.** `go test ./...` exits 0 from the repo
   root.
3. **Controller tests are green and include the new coverage.**
   `go test ./internal/controller/...` exits 0, and the test binary
   reports tests covering at least:
   - cleanup loop startup with `PROMETHEUS_ADDRESS` unset (graceful
     shutdown);
   - `parseMonitoringEnv()` returning a non-nil env when the address is
     unset;
   - eligibility-based deletion of a CAV with no `deletionRules` when no
     Prometheus client is available;
   - skipping (no deletion, no panic, no error-driven requeue storm) of a
     CAV with `deletionRules` when no Prometheus client is available;
   - rate-limited reachability probing (at most one `runtimeinfo` request
     per `acquireClientRetryDelay` window across consecutive cycles).
4. **Early-return is gone.** `internal/controller/version-monitoring.go`
   no longer contains an `if mEnv == nil { return }` (or equivalent
   early `return`) inside `startVersionCleanup`. The function always
   reaches the goroutine-launching code path for any non-cancelled
   context.
5. **Annotation contract is unchanged.** A `grep` for
   `AnnotationEnableCleanupMonitoring` over `internal/controller/`
   shows the same accepted values (`"true"`, `"dry-run"`,
   case-insensitive) — no new accepted values, no inverted defaults,
   no removal of the existing filter in
   `queueVersionsForCleanupEvaluation`.
6. **API types and CRDs untouched.** `git diff` against the merge base
   shows no changes under `pkg/apis/sme.sap.com/v1alpha1/`,
   `pkg/client/`, or `crds/`.
7. **Documentation reflects the new behaviour.**
   - `website/content/en/docs/configuration/_index.md` no longer claims
     that version monitoring is disabled when `PROMETHEUS_ADDRESS` is
     unset; instead, it states that the cleanup loop still runs and
     describes which versions are eligible without Prometheus.
   - `website/content/en/docs/usage/version-monitoring.md` ("Integration
     with Prometheus" and "Evaluating CAPApplicationVersion Resources
     for Cleanup" sections) describes the new contract: cleanup runs
     unconditionally, workloads without `deletionRules` are eligible
     without Prometheus, workloads with `deletionRules` are skipped
     until Prometheus is reachable.
