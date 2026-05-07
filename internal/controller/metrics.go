/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"net/url"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	k8sclientmetrics "k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/util/workqueue"
)

// Constants for the metrics
const (
	CAPOp = "cap_op"
	Queue = "queue"
	// Metrics for workqueue
	Depth                   = "depth"
	Adds                    = "adds_total"
	QueueLatency            = "latency_seconds"
	WorkDuration            = "work_duration_seconds"
	UnfinishedWork          = "unfinished_work_seconds"
	LongestRunningProcessor = "longest_running_processor_seconds"
	Retries                 = "retries_total"
)

var (
	// Metrics for CROs in Error (Kind along with namespace & name of the CRO)
	ReconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "reconcile_errors",
		Help:      "Resources that failed to reconcile",
	}, []string{"kind", "namespace", "name"})

	// Metrics for CROs in Panic (namespace-name of the CRO)
	Panics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "panics",
		Help:      "Resources that caused a panic",
	}, []string{"kind", "namespace", "name"})

	// Metrics for overall tenant operations
	TenantOperations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "tenant_operations",
		Help:      "Overall number of tenant operations",
	}, []string{"app", "operation"})

	// Metrics for TenantOperation Failures (with app, operation, namespace & name of the tenant operation)
	TenantOperationFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "tenant_operation_failures",
		Help:      "Tenant operations that failed to complete",
	}, []string{"app", "operation", "tenant_id", "namespace", "name"})

	// Metrics for duration of TenantOperations (could help with determining duration of saas provisioning callback for e.g.)
	LastTenantOperationDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: CAPOp,
		Name:      "last_tenant_operation_duration_seconds",
		Help:      "Duration of last tenant operation in seconds",
	}, []string{"app", "tenant_id"})

	// Metrics for overall service operations
	ServiceOperations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "service_operations",
		Help:      "Overall number of service operations",
	}, []string{"app"})

	// Metrics for overall service operations
	ServiceOperationFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "service_operation_failures",
		Help:      "Service Operations that failed to complete",
	}, []string{"app", "version", "namespace", "name"})

	/**
		Note:
		All the metrics below are for the CAP Operator controller workqueue,
		used for handling CAP Operator resources.
		These need to be explicitly defined here along with a capOperatorMetricsProvider,
		as we have our own controller/workqueue implementation.
	**/

	depth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      Depth,
		Help:      "Depth of workqueue",
	}, []string{"name"})

	adds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      Adds,
		Help:      "Adds to workqueue",
	}, []string{"name"})

	latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      QueueLatency,
		Help:      "Latency of workqueue",
		Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
	}, []string{"name"})

	workDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      WorkDuration,
		Help:      "Processing time of workqueue",
		Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
	}, []string{"name"})

	unfinished = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      UnfinishedWork,
		Help:      "Unfinished work in workqueue",
	}, []string{"name"})

	longestRunningProcessor = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      LongestRunningProcessor,
		Help:      "Longest running processor in workqueue",
	}, []string{"name"})

	retries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Subsystem: Queue,
		Name:      Retries,
		Help:      "Retries in workqueue",
	}, []string{"name"})

	// K8s client-go metrics aren't exposed. This is a copy of: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/metrics/prometheus/restclient/metrics.go#L78
	rateLimiterLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: CAPOp,
		Name:      "rest_client_rate_limiter_duration_seconds",
		Help:      "Client side rate limiter latency in seconds. Broken down by verb, and host.",
		Buckets:   []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0},
	},
		[]string{"verb", "host"},
	)

	// K8s client-go metrics aren't exposed. This is a copy of: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/metrics/prometheus/restclient/metrics.go#L88
	requestResult = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: CAPOp,
		Name:      "rest_client_requests_total",
		Help:      "Number of HTTP requests, partitioned by status code, method, and host.",
	}, []string{"code", "method", "host"})
)

// #region k8sRequestResultProvider
// This isn't exposed by K8s, so we made a copy of: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/metrics/prometheus/restclient/metrics.go#L252
type k8sRequestResultProvider struct {
	m *prometheus.CounterVec
}

func (p *k8sRequestResultProvider) Increment(_ context.Context, code string, method string, host string) {
	p.m.WithLabelValues(code, method, host).Inc()
}

type k8sRequestlatencyAdapter struct {
	m *prometheus.HistogramVec
}

func (l *k8sRequestlatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	l.m.WithLabelValues(verb, u.Host).Observe(latency.Seconds())
}

// #endregion

// Create a variable to hold all the collectors
var collectors = []prometheus.Collector{ReconcileErrors, Panics, TenantOperations, ServiceOperations, depth, adds, latency, workDuration, unfinished, longestRunningProcessor, retries, requestResult}

// #region capOperatorMetricsProvider
// capOperatorMetricsProvider implements workqueue.MetricsProvider
type capOperatorMetricsProvider struct {
}

func (capOperatorMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return depth.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return adds.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return latency.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return workDuration.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return unfinished.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return longestRunningProcessor.WithLabelValues(name)
}

func (capOperatorMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return retries.WithLabelValues(name)
}

// #endregion

// Initialize the metrics
func initializeMetrics() {
	// Parse DETAILED_OPERATIONAL_METRICS env. to determine if detailed operation metrics are needed
	if os.Getenv("DETAILED_OPERATIONAL_METRICS") == "true" {
		collectors = append(collectors, TenantOperationFailures, ServiceOperationFailures, LastTenantOperationDuration)
	}

	// Register CAP Operator metrics
	prometheus.MustRegister(collectors...)

	// Register Kubernetes client-go REST API metrics with the custom k8sRequestResultProvider
	k8sclientmetrics.Register(k8sclientmetrics.RegisterOpts{
		RequestResult:      &k8sRequestResultProvider{requestResult},
		RateLimiterLatency: &k8sRequestlatencyAdapter{rateLimiterLatency},
	})

	// Register CAP Operator metrics provider as the workqueue metrics provider (needed for the workqueue metrics, to be done just once)
	workqueue.SetProvider(capOperatorMetricsProvider{})
}

func deregisterMetrics() {
	// Un-register CAP Operator metrics
	for _, collector := range collectors {
		prometheus.Unregister(collector)
	}
}
