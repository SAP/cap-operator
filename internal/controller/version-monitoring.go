/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	prommodel "github.com/prometheus/common/model"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	EnvPrometheusAddress                 = "PROMETHEUS_ADDRESS"
	EnvPrometheusAcquireClientRetryDelay = "PROM_ACQUIRE_CLIENT_RETRY_DELAY" // Value should be a duration
	EnvMetricsEvaluationInterval         = "METRICS_EVAL_INTERVAL"
)

const (
	CAPApplicationVersionEventReadForDeletion = "ReadyForDeletion"
	EventActionEvaluateMetrics                = "EvaluateMetrics"
)

const (
	GaugeEvaluationExpression   = "sum(avg_over_time(%s{job=\"%s\",namespace=\"%s\"}[%s]))"
	CounterEvaluationExpression = "sum(rate(%s{job=\"%s\",namespace=\"%s\"}[%s]))"
)

// promClientProvider abstracts Prometheus API availability so that each
// evaluation cycle can obtain the current API client without making a network
// call on every iteration. A nil promClientProvider means no address is
// configured; callers must guard with a nil check before calling Get.
type promClientProvider interface {
	// Get returns the current Prometheus API and true when available, or
	// (nil, false) when the server is unreachable.
	Get(ctx context.Context) (promv1.API, bool)
}

// cachedPromClientProvider holds a cached Prometheus API client and manages
// reachability probing with a configurable delay between probes.
type cachedPromClientProvider struct {
	address    string
	retryDelay time.Duration

	mu          sync.Mutex
	cached      promv1.API // non-nil when the last probe succeeded
	lastProbeAt time.Time  // when the last probe (success or failure) was attempted
	loggedError bool       // true after we have logged the first construction/probe failure
}

// Get returns the cached Prometheus API when available. When unavailable it
// probes at most once per retryDelay window.
func (p *cachedPromClientProvider) Get(ctx context.Context) (promv1.API, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Fast path: already have a working client.
	if p.cached != nil {
		return p.cached, true
	}

	// Only probe if enough time has passed since the last attempt.
	if time.Since(p.lastProbeAt) < p.retryDelay {
		return nil, false
	}

	// Attempt to construct a client and verify reachability.
	p.lastProbeAt = time.Now()

	client, err := promapi.NewClient(promapi.Config{Address: p.address})
	if err != nil {
		if !p.loggedError {
			klog.ErrorS(err, "could not create prometheus client", "address", p.address)
			p.loggedError = true
		}
		return nil, false
	}

	api := promv1.NewAPI(client)
	_, err = api.Runtimeinfo(ctx)
	if err != nil {
		if !p.loggedError {
			klog.ErrorS(err, "could not fetch runtime info from prometheus server", "address", p.address)
			p.loggedError = true
		}
		return nil, false
	}

	// Probe succeeded — cache the client and reset the error flag.
	klog.InfoS("prometheus server is now reachable", "address", p.address)
	p.cached = api
	p.loggedError = false
	return p.cached, true
}

// newPromClientProvider returns a cachedPromClientProvider when an address is
// configured, or nil when PROMETHEUS_ADDRESS is unset.
func newPromClientProvider(mEnv *monitoringEnv) promClientProvider {
	if mEnv.address == "" {
		return nil
	}
	return &cachedPromClientProvider{
		address:    mEnv.address,
		retryDelay: mEnv.acquireClientRetryDelay,
		// lastProbeAt is zero so the first call triggers an immediate probe.
	}
}

// cleanupOrchestrator holds the state needed by the version-cleanup routines.
type cleanupOrchestrator struct {
	clientProvider promClientProvider
	queue          workqueue.TypedRateLimitingInterface[NamespacedResourceKey]
	mEnv           *monitoringEnv
}

type monitoringEnv struct {
	address                 string
	acquireClientRetryDelay time.Duration
	evaluationInterval      time.Duration
}

// parseMonitoringEnv always returns a non-nil *monitoringEnv.
// When PROMETHEUS_ADDRESS is unset or whitespace-only, address is set to the
// empty string; the duration fields are still populated from their respective
// env vars (with the same defaults as before).
func parseMonitoringEnv() *monitoringEnv {
	env := &monitoringEnv{
		address: strings.TrimSpace(os.Getenv(EnvPrometheusAddress)),
	}

	evalDurationEnv := func(envName string, fallback time.Duration) time.Duration {
		if v, ok := os.LookupEnv(envName); ok && strings.TrimSpace(v) != "" {
			dur, err := time.ParseDuration(strings.TrimSpace(v))
			if err == nil {
				return dur
			}
		}
		return fallback
	}
	env.acquireClientRetryDelay = evalDurationEnv(EnvPrometheusAcquireClientRetryDelay, time.Hour)
	env.evaluationInterval = evalDurationEnv(EnvMetricsEvaluationInterval, 10*time.Minute)
	return env
}

// startVersionCleanup starts the version-cleanup schedule and worker goroutines
// for the lifetime of ctx. It no longer short-circuits when there is no
// Prometheus address configured — workloads without deletionRules are still
// eligible for cleanup.
func (c *Controller) startVersionCleanup(ctx context.Context) {
	mEnv := parseMonitoringEnv()

	if mEnv.address == "" {
		klog.InfoS("PROMETHEUS_ADDRESS is not set; only versions without deletion rules will be cleaned up")
	}

	restartSignal := make(chan bool, 1)
	setup := func() context.CancelFunc {
		o := initializeVersionCleanupOrchestrator(mEnv)
		child, cancelFn := context.WithCancel(ctx)
		go func() {
			<-child.Done()
			o.queue.ShutDown()
		}()
		go c.scheduleVersionCollectionForCleanup(child, o, restartSignal)
		go c.processVersionCleanupQueue(child, o, restartSignal)
		return cancelFn
	}

	for {
		cancel := setup()
		select {
		case <-ctx.Done():
			cancel()
			return
		case <-restartSignal: // restart broken routines
			cancel()
		}
	}
}

func recoverVersionCleanupRoutine(restart chan<- bool) {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic@version-cleanup: %v", r)
		klog.ErrorS(err, "recovered from panic")
		select { // send restart signal restart process
		case restart <- true: // send to channel if empty (channel size 1)
		default:
		}
	}
}

// initializeVersionCleanupOrchestrator always returns a non-nil
// *cleanupOrchestrator. It sets up the work queue and the Prometheus client
// provider but does NOT block on, or return nil because of, Prometheus
// reachability.
func initializeVersionCleanupOrchestrator(mEnv *monitoringEnv) *cleanupOrchestrator {
	return &cleanupOrchestrator{
		clientProvider: newPromClientProvider(mEnv),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[NamespacedResourceKey]()),
		mEnv:           mEnv,
	}
}

func (c *Controller) scheduleVersionCollectionForCleanup(ctx context.Context, orc *cleanupOrchestrator, restart chan<- bool) {
	defer recoverVersionCleanupRoutine(restart)
	for {
		if err := c.queueVersionsForCleanupEvaluation(orc); err != nil {
			klog.ErrorS(err, "could not select applications for version cleanup evaluation")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(orc.mEnv.evaluationInterval): // sleep for (say 10m) before reading versions again
			continue
		}
	}
}

func (c *Controller) queueVersionsForCleanupEvaluation(orc *cleanupOrchestrator) error {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister()
	cas, err := lister.List(labels.Everything())
	if err != nil {
		return err
	}

	for i := range cas {
		ca := cas[i]
		if v, ok := ca.Annotations[AnnotationEnableCleanupMonitoring]; !ok || !(strings.ToLower(v) == "true" || strings.ToLower(v) == "dry-run") {
			continue
		}
		outdated, err := c.getCleanupRelevantVersions(ca)
		if err != nil || len(outdated) == 0 {
			continue
		}
		for n := range outdated {
			cav := outdated[n]
			orc.queue.Add(NamespacedResourceKey{Namespace: cav.Namespace, Name: cav.Name})
		}
	}
	return nil
}

func (c *Controller) getCleanupRelevantVersions(ca *v1alpha1.CAPApplication) ([]*v1alpha1.CAPApplicationVersion, error) {
	excludedVersions := map[string]bool{}
	excludedVersionNames := map[string]bool{}

	selector, _ := labels.ValidatedSelectorFromSet(map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(ca.Namespace, ca.Name),
	})
	tenantLister := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister()
	cats, err := tenantLister.CAPTenants(ca.Namespace).List(selector)
	if err != nil {
		return nil, err
	}
	for i := range cats {
		cat := cats[i]
		if cat.Spec.Version != "" {
			excludedVersions[cat.Spec.Version] = true
		}
		if cat.Status.CurrentCAPApplicationVersionInstance != "" {
			excludedVersionNames[cat.Status.CurrentCAPApplicationVersionInstance] = true
		}
	}

	latestReadyVersion, err := c.getLatestReadyCAPApplicationVersion(ca, true)
	if err != nil || latestReadyVersion == nil {
		// if there are no Ready versions yet - do not initiate cleanup
		return nil, err
	}

	// Explicitly exclude the latest Ready version from cleanup
	excludedVersions[latestReadyVersion.Spec.Version] = true

	outdatedVersions := []*v1alpha1.CAPApplicationVersion{}
	cavs, _ := c.getCachedCAPApplicationVersions(ca) // ignoring error as this is not critical
	for i := range cavs {
		cav := cavs[i]
		// ignore all versions greater than latest Ready one
		if semver.Compare("v"+cav.Spec.Version, "v"+latestReadyVersion.Spec.Version) == 1 {
			continue
		}
		if excludedVersions[cav.Spec.Version] || excludedVersionNames[cav.Name] {
			continue // filter out versions attached to tenants
		}
		outdatedVersions = append(outdatedVersions, cav)
	}

	return outdatedVersions, nil
}

func (c *Controller) processVersionCleanupQueue(ctx context.Context, orc *cleanupOrchestrator, restart chan<- bool) {
	defer recoverVersionCleanupRoutine(restart)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if c.processVersionCleanupQueueItem(ctx, orc) {
				return
			}
		}
	}
}

// processVersionCleanupQueueItem dequeues one item and evaluates it for
// cleanup. It obtains the current Prometheus API from the provider; if the
// provider reports unavailable, nil is passed to the evaluator so that
// workloads without deletionRules can still be cleaned up.
func (c *Controller) processVersionCleanupQueueItem(ctx context.Context, orc *cleanupOrchestrator) (stop bool) {
	item, shutdown := orc.queue.Get()
	if shutdown {
		return true // stop processing
	}
	defer orc.queue.Done(item)

	// Obtain the current Prometheus API — nil when address is unconfigured or server unreachable.
	var api promv1.API
	if orc.clientProvider != nil {
		api, _ = orc.clientProvider.Get(ctx)
	}

	if c.evaluateVersionForCleanup(ctx, item, api) != nil {
		orc.queue.AddRateLimited(item)
	} else {
		orc.queue.Forget(item)
	}
	return false
}

// evaluateVersionForCleanup evaluates one CAPApplicationVersion for deletion
// eligibility. promapi may be nil when Prometheus is unavailable; in that
// case workloads that require deletionRules are considered not eligible (kept
// for re-evaluation next cycle) while workloads without deletionRules remain
// automatically eligible.
func (c *Controller) evaluateVersionForCleanup(ctx context.Context, item NamespacedResourceKey, promapi promv1.API) error {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister()
	cav, err := lister.CAPApplicationVersions(item.Namespace).Get(item.Name)
	if err != nil {
		return handleOperatorResourceErrors(err)
	}

	// read CAPApplication to determine dry-run mode
	ca, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(cav.Namespace).Get(cav.Spec.CAPApplicationInstance)
	if err != nil {
		return err
	}

	cleanup := true
	for i := range cav.Spec.Workloads {
		wl := cav.Spec.Workloads[i]
		if !evaluateWorkloadForCleanup(ctx, item, &wl, promapi) {
			cleanup = false
			break
		}
	}

	if cleanup {
		klog.InfoS("version has been evaluated to be ready for deletion", "version", cav.Name)
		c.Event(cav, nil, corev1.EventTypeNormal, CAPApplicationVersionEventReadForDeletion, EventActionEvaluateMetrics, fmt.Sprintf("version %s is now ready for deletion", cav.Name))

		if v, ok := ca.Annotations[AnnotationEnableCleanupMonitoring]; ok && strings.ToLower(v) == "true" {
			return c.crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).Delete(ctx, cav.Name, v1.DeleteOptions{})
		}
	}

	return nil
}

// evaluateWorkloadForCleanup decides whether a single workload is eligible for
// cleanup.
//
//   - When the workload has no deletionRules, it is automatically eligible
//     (returns true) regardless of Prometheus availability.
//   - When deletionRules are present but promapi is nil (Prometheus
//     unavailable), the workload is NOT eligible (returns false) and a
//     single informational log entry is emitted.
//   - When deletionRules are present and promapi is available, the rules are
//     evaluated via the existing helpers.
func evaluateWorkloadForCleanup(ctx context.Context, cav NamespacedResourceKey, wl *v1alpha1.WorkloadDetails, promapi promv1.API) bool {
	if wl.DeploymentDefinition == nil || wl.DeploymentDefinition.Monitoring == nil || wl.DeploymentDefinition.Monitoring.DeletionRules == nil {
		return true // if there are no rules - the workload is automatically eligible for cleanup
	}

	// Deletion rules are present; we need Prometheus to evaluate them.
	if promapi == nil {
		klog.InfoS("prometheus client unavailable; workload with deletion rules cannot be evaluated and will be skipped",
			"workload", wl.Name, "version", cav.Name)
		return false
	}

	if wl.DeploymentDefinition.Monitoring.DeletionRules.ScalarExpression != nil { // evaluate provided expression
		isRelevantForCleanup, err := evaluateExpression(ctx, *wl.DeploymentDefinition.Monitoring.DeletionRules.ScalarExpression, promapi)
		if err != nil {
			klog.ErrorS(err, "could not evaluate PromQL expression for workload", "workload", wl.Name, "version", cav.Name)
			return false
		}
		return isRelevantForCleanup
	}

	// evaluate rules based on metric type
	for j := range wl.DeploymentDefinition.Monitoring.DeletionRules.Metrics {
		rule := wl.DeploymentDefinition.Monitoring.DeletionRules.Metrics[j]
		isRelevantForCleanup, err := evaluateMetric(ctx, &rule, fmt.Sprintf("%s%s", getWorkloadName(cav.Name, wl.Name), ServiceSuffix), cav.Namespace, promapi)
		if err != nil {
			klog.ErrorS(err, "could not evaluate metric for workload", "workload", wl.Name, "version", cav.Name)
			return false
		}
		if !isRelevantForCleanup {
			return false
		}
	}
	return true
}

func executePromQL(ctx context.Context, promapi promv1.API, query string) (prommodel.Value, error) {
	// klog.InfoS("executing prometheus query", "query", query)
	result, warnings, err := promapi.Query(ctx, query, time.Now())
	if err != nil {
		klog.ErrorS(err, "prometheus query error", "query", query)
		return nil, err
	}
	if len(warnings) > 0 {
		klog.InfoS(fmt.Sprintf("query %s returned warnings [%s]", query, strings.Join(warnings, ", ")))
	}
	klog.InfoS(fmt.Sprintf("query %s returned result: %v", query, result))
	return result, nil
}

func evaluateExpression(ctx context.Context, rawExpr string, promapi promv1.API) (bool, error) {
	expr := strings.TrimSpace(rawExpr)
	if expr == "" {
		return false, fmt.Errorf("encountered empty expression")
	}

	result, err := executePromQL(ctx, promapi, expr)
	if err != nil {
		return false, err
	}

	s, ok := result.(*prommodel.Scalar)
	if !ok {
		err := fmt.Errorf("result from query %s could not be casted as a scalar", expr)
		klog.ErrorS(err, "error parsing query result")
		return false, err
	}

	return s.Value == 1, nil // expecting a boolean result
}

func evaluateMetric(ctx context.Context, rule *v1alpha1.MetricRule, job, ns string, promapi promv1.API) (bool, error) {
	query := ""
	switch rule.Type {
	case v1alpha1.MetricTypeGauge:
		query = fmt.Sprintf(GaugeEvaluationExpression, rule.Name, job, ns, rule.CalculationPeriod)
	case v1alpha1.MetricTypeCounter:
		query = fmt.Sprintf(CounterEvaluationExpression, rule.Name, job, ns, rule.CalculationPeriod)
	default:
		return false, fmt.Errorf("metric %s has unsupported type %s", rule.Name, rule.Type)
	}

	result, err := executePromQL(ctx, promapi, query)
	if err != nil {
		return false, err
	}

	vec, ok := result.(prommodel.Vector)
	if !ok {
		err := fmt.Errorf("result from query %s could not be casted as a vector", query)
		klog.ErrorS(err, "error parsing query result")
		return false, err
	}
	if len(vec) > 0 {
		sample := vec[0] // use the first one - expecting only one sample based on the expressions
		var threshold prommodel.SampleValue
		err = threshold.UnmarshalJSON(fmt.Appendf(nil, "\"%s\"", rule.ThresholdValue))
		if err != nil {
			klog.ErrorS(err, "error parsing threshold value", "value", rule.ThresholdValue, "metric", rule.Name)
			return false, err
		}
		klog.InfoS("parsed prometheus query result and threshold", "threshold", threshold.String(), "query_result", sample.Value.String(), "query", query)
		return sample.Value <= threshold, nil
	} else {
		// there could be no results if the version was not transmitting metrics for a very long time
		return true, nil
	}
}
