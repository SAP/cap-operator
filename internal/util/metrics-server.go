/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

// Initializes the metrics server with default port 9090 and path /metrics based on default prometheus client
func InitMetricsServer() {
	// Expose /metrics HTTP endpoint
	go func() {
		// Default port
		metricsPort := "9090"

		// Get Port from env
		portEnv := os.Getenv("METRICS_PORT")
		if portEnv != "" {
			metricsPort = portEnv
		}
		http.Handle("/metrics", promhttp.Handler())
		klog.Fatal(http.ListenAndServe(":"+metricsPort, nil))
	}()
}

// Instruments the given HTTP handler with counter (total requests) and gauge (in flight requests) metrics
func InstrumentHttpHandler(handler func(http.ResponseWriter, *http.Request), metricNamePrefix string, helpTextSuffix string) http.HandlerFunc {
	klog.InfoS("Instrumenting HTTP handler", "metricPrefix", metricNamePrefix, "helpSuffix", helpTextSuffix)
	return promhttp.InstrumentHandlerCounter(
		promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricNamePrefix + "_total",
				Help: "Total " + helpTextSuffix,
			},
			[]string{"code", "method"},
		),
		promhttp.InstrumentHandlerInFlight(promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: metricNamePrefix + "_in_flight",
				Help: "Current " + helpTextSuffix,
			},
		),
			http.HandlerFunc(handler),
		),
	)
}
