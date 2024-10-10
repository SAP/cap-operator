/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
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
)

// Create a varaible to hold all the collectors
var collectors = []prometheus.Collector{ReconcileErrors, Panics, TenantOperations, depth, adds, latency, workDuration, unfinished, longestRunningProcessor, retries}

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
		collectors = append(collectors, TenantOperationFailures, LastTenantOperationDuration)
	}

	// Register CAP Operator metrics
	prometheus.MustRegister(collectors...)

	// Register CAP Operator metrics provider as the workqueue metrics provider (needed for the workqueue metrics, to be done just once)
	workqueue.SetProvider(capOperatorMetricsProvider{})
}

func deregisterMetrics() {
	// Un-register CAP Operator metrics
	for _, collector := range collectors {
		prometheus.Unregister(collector)
	}
}
