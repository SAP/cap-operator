/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prommodel "github.com/prometheus/common/model"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/workqueue"
)

func TestMonitoringEnv(t *testing.T) {
	expAdd := "http://prom.server.local"
	expAcqRetryInt := "10s"
	expEvalInt := "3h"
	tests := []struct {
		add         *string
		acqRetryInt *string
		evalInt     *string
	}{
		{},
		{add: &expAdd, acqRetryInt: &expAcqRetryInt, evalInt: &expEvalInt},
		{add: &expAdd},
	}

	for _, tt := range tests {
		t.Run("test monitoring env", func(t *testing.T) {
			if tt.add != nil {
				os.Setenv(EnvPrometheusAddress, *tt.add)
				defer os.Unsetenv(EnvPrometheusAddress)
			}
			if tt.acqRetryInt != nil {
				os.Setenv(EnvPrometheusAcquireClientRetryDelay, *tt.acqRetryInt)
				defer os.Unsetenv(EnvPrometheusAcquireClientRetryDelay)
			}
			if tt.evalInt != nil {
				os.Setenv(EnvMetricsEvaluationInterval, *tt.evalInt)
				defer os.Unsetenv(EnvMetricsEvaluationInterval)
			}

			mEnv := parseMonitoringEnv()

			if tt.add == nil {
				// New contract: always returns non-nil *monitoringEnv with empty address.
				if mEnv == nil {
					t.Errorf("expected non-nil monitoringEnv even when PROMETHEUS_ADDRESS is unset")
					return
				}
				if mEnv.address != "" {
					t.Errorf("expected empty address when PROMETHEUS_ADDRESS is unset, got %q", mEnv.address)
				}
				if mEnv.acquireClientRetryDelay != time.Hour {
					t.Errorf("expected default acquire client retry interval (1h), got %v", mEnv.acquireClientRetryDelay)
				}
				if mEnv.evaluationInterval != 10*time.Minute {
					t.Errorf("expected default evaluation interval (10m), got %v", mEnv.evaluationInterval)
				}
				return
			}
			if tt.acqRetryInt != nil {
				exp, _ := time.ParseDuration(*tt.acqRetryInt)
				if mEnv.acquireClientRetryDelay != exp {
					t.Errorf("expected acquire client retry interval to be %s", *tt.acqRetryInt)
				}
			} else {
				if mEnv.acquireClientRetryDelay != time.Hour {
					t.Errorf("expected default acquire client retry interval")
				}
			}
			if tt.evalInt != nil {
				exp, _ := time.ParseDuration(*tt.evalInt)
				if mEnv.evaluationInterval != exp {
					t.Errorf("expected evaluation interval to be %s", *tt.evalInt)
				}
			} else {
				if mEnv.evaluationInterval != 10*time.Minute {
					t.Errorf("expected default evaluation interval")
				}
			}
		})
	}
}

func setupTestControllerWithInitialResources(t *testing.T, initialResources []string) *Controller {
	c := initializeControllerForReconciliationTests(t, []ResourceAction{}, []schema.GroupVersionResource{})
	var wg sync.WaitGroup
	work := func(file string) {
		defer wg.Done()
		raw, err := readYAMLResourcesFromFile(file)
		if err != nil {
			t.Errorf("error reading resources from file %s: %s", file, err.Error())
			return
		}
		for j := range raw {
			err = addInitialObjectToStore(raw[j], c)
			if err != nil {
				t.Error(err)
				return
			}
		}
	}

	for i := range initialResources {
		wg.Add(1)
		go work(initialResources[i])
	}
	wg.Wait()

	return c
}

func TestGracefulShutdownMonitoringRoutines(t *testing.T) {
	t.Run("with PROMETHEUS_ADDRESS set", func(t *testing.T) {
		defer deregisterMetrics()

		c := setupTestControllerWithInitialResources(t, []string{})

		s, _ := getPromServer(false, []queryTestCase{})
		defer s.Close()

		os.Setenv(EnvPrometheusAddress, s.URL)
		defer os.Unsetenv(EnvPrometheusAddress)

		testCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var wg sync.WaitGroup
		wg.Go(func() {
			c.startVersionCleanup(testCtx)
		})
		wg.Wait() // goroutines must exit when context is cancelled — or the test times out
	})

	t.Run("without PROMETHEUS_ADDRESS set", func(t *testing.T) {
		defer deregisterMetrics()

		// Ensure the env var is not set.
		os.Unsetenv(EnvPrometheusAddress)

		c := setupTestControllerWithInitialResources(t, []string{})

		testCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var wg sync.WaitGroup
		wg.Go(func() {
			c.startVersionCleanup(testCtx)
		})
		wg.Wait() // goroutines must exit when context is cancelled — or the test times out
	})
}

func TestVersionSelectionForCleanup(t *testing.T) {
	tests := []struct {
		name             string
		resources        []string
		expectedVersions []string
		expectError      bool
	}{
		{
			name: "select versions not assigned to tenants",
			resources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v3-deletion-rules.yaml",
				"testdata/version-monitoring/cat-provider-v3-ready.yaml",
			},
			expectedVersions: []string{"default.test-cap-01-cav-v1", "default.test-cap-01-cav-v2"},
		},
		{
			name: "version cleanup must ignore CAPApplications without specified annotation",
			resources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v3-deletion-rules.yaml",
				"testdata/version-monitoring/cat-provider-v3-ready.yaml",
			},
			expectedVersions: []string{},
		},
		{
			name: "should not consider versions higher than the latest Ready version",
			resources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v3-deletion-rules-processing.yaml",
				"testdata/version-monitoring/cat-provider-v2-ready.yaml",
			},
			expectedVersions: []string{"default.test-cap-01-cav-v1"},
		},
		{
			name: "should not consider any version when there are no Ready versions",
			resources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v3-deletion-rules-processing.yaml",
			},
			expectedVersions: []string{},
		},
		{
			name: "should not consider versions with tenants (using dry-run)",
			resources: []string{
				"testdata/version-monitoring/ca-cleanup-dry-run-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
				"testdata/version-monitoring/cav-v3-deletion-rules.yaml",
				"testdata/version-monitoring/cat-consumer-v2-upgrading.yaml",
			},
			expectedVersions: []string{"default.test-cap-01-cav-v1"},
		},
	}

	getQueuedItems := func(o *cleanupOrchestrator) []string {
		res := []string{}
		for {
			i, stop := o.queue.Get()
			if stop {
				return res
			}
			o.queue.Done(i)
			res = append(res, fmt.Sprintf("%s.%s", i.Namespace, i.Name))
			o.queue.Forget(i)
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Deregister metrics at the end of the test
			defer deregisterMetrics()

			c := setupTestControllerWithInitialResources(t, tc.resources)
			orc := &cleanupOrchestrator{queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[NamespacedResourceKey]())}
			defer orc.queue.ShutDown()
			err := c.queueVersionsForCleanupEvaluation(orc)
			if err != nil {
				if !tc.expectError {
					t.Errorf("not expecting error for test case %s -> error: %s", tc.name, err.Error())
				}
				return
			}
			evs := map[string]bool{}
			for _, s := range tc.expectedVersions {
				evs[s] = false
			}
			orc.queue.ShutDownWithDrain() // allows existing items to be processed before shutting down
			results := getQueuedItems(orc)
			for _, r := range results {
				if _, ok := evs[r]; ok {
					evs[r] = true
				} else {
					t.Errorf("unexpected version %s queued for cleanup", r)
				}
			}
			for exp, found := range evs {
				if !found {
					t.Errorf("was expecting version %s to be queued for cleanup", exp)
				}
			}
		})
	}
}

type queryTestCase struct {
	expectedQuery       string
	simulateError       bool
	simulateEmptyResult bool
	simulatedResultType string // vector | scalar | invalid
	simulatedValue      float64
}

type evalTestConfig struct {
	name             string
	evaluatedVersion string
	startResources   []string
	expectCleanup    bool
	expectError      bool
	cases            []queryTestCase
}

func mockPromRuntimeInfoHandler(simError bool, w http.ResponseWriter) {
	if simError {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		io.WriteString(w, `
			{
				"status": "success",
				"data": {
					"CWD": "/",
					"goroutineCount": 48,
					"GOMAXPROCS": 4
				}
			}
		`)
	}
}

func mockPromQueryHandler(testCases []queryTestCase, query string, w http.ResponseWriter) {
	var tCase *queryTestCase
	for i := range testCases {
		tc := testCases[i]
		if tc.expectedQuery == query {
			tCase = &tc
			break
		}
	}
	if tCase == nil {
		io.WriteString(w, `
			{
				"status": "error",
				"errorType": "TestCaseMismatch",
				"error": "could not match received query to a specified test case"
			}
		`)
		return
	}
	if tCase.simulateError {
		io.WriteString(w, `
			{
				"status": "error",
				"errorType": "SimulatedError",
				"error": "simulated error"
			}
		`)
		return
	}
	if tCase.simulateEmptyResult {
		io.WriteString(w,
			fmt.Sprintf(`{
				"status": "success",
				"data": {
					"resultType": "%s",
					"result": []
				}
			}`, tCase.simulatedResultType),
		)
	}

	getScalar := func() *prommodel.Scalar {
		return &prommodel.Scalar{
			Timestamp: prommodel.Now(),
			Value:     prommodel.SampleValue(tCase.simulatedValue),
		}
	}

	getVector := func() *prommodel.Vector {
		return &prommodel.Vector{{
			Timestamp: prommodel.Now(),
			Value:     prommodel.SampleValue(tCase.simulatedValue),
			Metric:    prommodel.Metric{},
		}}
	}

	var (
		raw []byte
		err error
	)
	switch tCase.simulatedResultType {
	case "scalar":
		raw, err = getScalar().MarshalJSON()
	case "vector":
		raw, err = json.Marshal(getVector())
	case "invalid":
		raw = []byte("{\"property\":\"invalid\"}")
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	val := string(raw)

	io.WriteString(w,
		fmt.Sprintf(`{
			"status": "success",
			"data": {
				"resultType": "%s",
				"result": %s
			}
		}`, tCase.simulatedResultType, val),
	)
}

// getPromServer starts a mock Prometheus HTTP server.
// When unavailable is true the /api/v1/status/runtimeinfo endpoint returns 503.
// The second return value is a function that returns the set of query strings
// that were received by the /api/v1/query endpoint; the third return value is a
// function that returns the total number of /api/v1/status/runtimeinfo requests
// that were received (useful for rate-limiting assertions).
func getPromServer(unavailable bool, cases []queryTestCase) (*httptest.Server, func() map[string]bool) {
	calledQueries := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/runtimeinfo" {
			mockPromRuntimeInfoHandler(unavailable, w)
			return
		}
		if r.URL.Path == "/api/v1/query" {
			q := r.FormValue("query")
			if q != "" {
				calledQueries[q] = false
			}
			mockPromQueryHandler(cases, q, w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // unexpected path
	}))
	return server, func() map[string]bool {
		return calledQueries
	}
}

// getPromServerWithCounter is like getPromServer but also returns an atomic
// counter tracking how many times /api/v1/status/runtimeinfo was called.
func getPromServerWithCounter(unavailable bool, cases []queryTestCase) (*httptest.Server, func() map[string]bool, *atomic.Int64) {
	calledQueries := map[string]bool{}
	var runtimeInfoHits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/runtimeinfo" {
			runtimeInfoHits.Add(1)
			mockPromRuntimeInfoHandler(unavailable, w)
			return
		}
		if r.URL.Path == "/api/v1/query" {
			q := r.FormValue("query")
			if q != "" {
				calledQueries[q] = false
			}
			mockPromQueryHandler(cases, q, w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	return server, func() map[string]bool { return calledQueries }, &runtimeInfoHits
}

func Test_initializeVersionCleanupOrchestrator(t *testing.T) {
	t.Run("initialize cleanup orchestrator - server available", func(t *testing.T) {
		s, _, hits := getPromServerWithCounter(false, []queryTestCase{})
		defer s.Close()

		o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
			address:                 s.URL,
			evaluationInterval:      2 * time.Minute,
			acquireClientRetryDelay: 30 * time.Second,
		})

		if o == nil {
			t.Fatal("expected non-nil orchestrator")
		}
		defer o.queue.ShutDown()

		// Provider should report the API as available on first probe.
		api, ok := o.clientProvider.Get(context.TODO())
		if !ok || api == nil {
			t.Errorf("expected provider to report prometheus API as available")
		}
		if hits.Load() == 0 {
			t.Errorf("expected at least one runtimeinfo probe to have been made")
		}
	})

	t.Run("initialize cleanup orchestrator - server unavailable", func(t *testing.T) {
		s, _, hits := getPromServerWithCounter(true, []queryTestCase{})
		defer s.Close()

		o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
			address:                 s.URL,
			evaluationInterval:      2 * time.Minute,
			acquireClientRetryDelay: 30 * time.Second,
		})

		if o == nil {
			t.Fatal("expected non-nil orchestrator even when server is unavailable")
		}
		defer o.queue.ShutDown()

		// Provider should immediately report unavailable (server returns 503).
		api, ok := o.clientProvider.Get(context.TODO())
		if ok || api != nil {
			t.Errorf("expected provider to report prometheus API as unavailable")
		}
		if hits.Load() == 0 {
			t.Errorf("expected at least one runtimeinfo probe to have been attempted")
		}
	})

	t.Run("initialize cleanup orchestrator - empty address", func(t *testing.T) {
		// Start a server but do NOT pass its URL to the orchestrator.
		s, _, hits := getPromServerWithCounter(false, []queryTestCase{})
		defer s.Close()

		o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
			address:                 "",
			evaluationInterval:      2 * time.Minute,
			acquireClientRetryDelay: 30 * time.Second,
		})

		if o == nil {
			t.Fatal("expected non-nil orchestrator when address is empty")
		}
		defer o.queue.ShutDown()

		// Provider must always report unavailable when address is empty.
		api, ok := o.clientProvider.Get(context.TODO())
		if ok || api != nil {
			t.Errorf("expected provider to report prometheus API as unavailable with empty address")
		}

		// The mock server must have received zero runtimeinfo hits.
		if hits.Load() != 0 {
			t.Errorf("expected zero runtimeinfo hits when address is empty, got %d", hits.Load())
		}
	})
}

func TestVersionCleanupEvaluation(t *testing.T) {
	tests := []evalTestConfig{
		{
			name:             "evaluate version with missing application - expect error",
			evaluatedVersion: "test-cap-01-cav-v1",
			startResources: []string{
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			},
			expectCleanup: false,
			expectError:   true,
			cases:         []queryTestCase{},
		},
		{
			name:             "evaluate version workloads - expecting deletion",
			evaluatedVersion: "test-cap-01-cav-v1",
			startResources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			},
			expectCleanup: true,
			expectError:   false,
			cases: []queryTestCase{
				{
					expectedQuery:       "sum(rate(total_http_requests{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[2m]))",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "vector",
					simulatedValue:      0.005,
				},
				{
					expectedQuery:       "sum(avg_over_time(active_jobs{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[3m]))",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "vector",
					simulatedValue:      0,
				},
				{
					expectedQuery:       "scalar(sum(avg_over_time(current_sessions{job=\"test-cap-01-cav-v1-app-router-svc\"}[12m]))) <= bool 1",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "scalar",
					simulatedValue:      1,
				},
			},
		},
		{
			name:             "evaluate version workloads - prom query error - from metric rule",
			evaluatedVersion: "test-cap-01-cav-v1",
			startResources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			},
			expectCleanup: false,
			expectError:   false,
			cases: []queryTestCase{
				{
					expectedQuery:       "sum(rate(total_http_requests{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[2m]))",
					simulateError:       true,
					simulateEmptyResult: false,
					simulatedResultType: "vector",
					simulatedValue:      0.005,
				},
			},
		},
		{
			name:             "evaluate version workloads - prom query error - from expression",
			evaluatedVersion: "test-cap-01-cav-v1",
			startResources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			},
			expectCleanup: false,
			expectError:   false,
			cases: []queryTestCase{
				{
					expectedQuery:       "sum(rate(total_http_requests{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[2m]))",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "vector",
					simulatedValue:      0.005,
				},
				{
					expectedQuery:       "sum(avg_over_time(active_jobs{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[3m]))",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "vector",
					simulatedValue:      0,
				},
				{
					expectedQuery:       "scalar(sum(avg_over_time(current_sessions{job=\"test-cap-01-cav-v1-app-router-svc\"}[12m]))) <= bool 1",
					simulateError:       true,
					simulateEmptyResult: false,
					simulatedResultType: "scalar",
					simulatedValue:      1,
				},
			},
		},
		{
			name:             "evaluate version workloads - prom query - invalid result type",
			evaluatedVersion: "test-cap-01-cav-v1",
			startResources: []string{
				"testdata/version-monitoring/ca-cleanup-enabled.yaml",
				"testdata/version-monitoring/cav-v1-deletion-rules-error.yaml",
				"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			},
			expectCleanup: false,
			expectError:   false,
			cases: []queryTestCase{
				{
					expectedQuery:       "sum(rate(total_http_requests{job=\"test-cap-01-cav-v1-cap-backend-srv-svc\",namespace=\"default\"}[2m]))",
					simulateError:       false,
					simulateEmptyResult: false,
					simulatedResultType: "invalid",
					simulatedValue:      0.005,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, getActualQueries := getPromServer(false, tt.cases)
			defer s.Close()
			o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{address: s.URL, acquireClientRetryDelay: 1 * time.Minute})
			defer o.queue.ShutDown()

			// Deregister metrics at the end of the test
			defer deregisterMetrics()

			c := setupTestControllerWithInitialResources(t, tt.startResources)
			item := NamespacedResourceKey{Namespace: "default", Name: tt.evaluatedVersion}
			o.queue.Add(item)
			_ = c.processVersionCleanupQueueItem(context.TODO(), o)

			// Verify error occurrence
			if tt.expectError {
				if o.queue.NumRequeues(item) == 0 {
					t.Errorf("expected requeue for version %s", tt.evaluatedVersion)
				}
			} else {
				if o.queue.NumRequeues(item) > 0 {
					t.Errorf("expected no requeues for version %s", tt.evaluatedVersion)
				}
			}

			// check whether expected queries were called
			act := getActualQueries()
			for _, c := range tt.cases {
				if _, ok := act[c.expectedQuery]; !ok {
					t.Errorf("expected query %s to be called", c.expectedQuery)
				} else {
					act[c.expectedQuery] = true
				}
			}
			for q, ok := range act {
				if !ok {
					t.Errorf("unexpected query %s was called", q)
				}
			}

			// verify version deletion
			_, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions("default").Get(context.TODO(), tt.evaluatedVersion, v1.GetOptions{})
			if tt.expectCleanup {
				if err == nil || !errors.IsNotFound(err) {
					t.Errorf("expected version %s to be deleted", tt.evaluatedVersion)
				}
			} else {
				if err != nil {
					t.Errorf("expected to fetch version %s", tt.evaluatedVersion)
				}
			}

		})
	}
}

// TestVersionCleanupEvaluation_NoPrometheus_NoDeletionRules verifies that a
// CAV whose workloads have NO deletionRules is deleted even when Prometheus is
// unavailable (empty address → noopPromClientProvider).
func TestVersionCleanupEvaluation_NoPrometheus_NoDeletionRules(t *testing.T) {
	defer deregisterMetrics()

	// v2 is the latest Ready version; v1 (no deletion rules) is outdated.
	c := setupTestControllerWithInitialResources(t, []string{
		"testdata/version-monitoring/ca-cleanup-enabled.yaml",
		"testdata/version-monitoring/cav-v1-no-deletion-rules.yaml",
		"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
		"testdata/version-monitoring/cat-provider-v2-ready.yaml",
	})

	o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
		address:                 "", // no Prometheus → noopPromClientProvider
		evaluationInterval:      10 * time.Minute,
		acquireClientRetryDelay: time.Hour,
	})
	defer o.queue.ShutDown()

	item := NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}
	o.queue.Add(item)
	_ = c.processVersionCleanupQueueItem(context.TODO(), o)

	// No requeues expected.
	if o.queue.NumRequeues(item) != 0 {
		t.Errorf("expected zero requeues for version without deletion rules, got %d", o.queue.NumRequeues(item))
	}

	// v1 must have been deleted.
	_, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions("default").Get(context.TODO(), "test-cap-01-cav-v1", v1.GetOptions{})
	if err == nil || !errors.IsNotFound(err) {
		t.Errorf("expected version test-cap-01-cav-v1 to be deleted when it has no deletion rules and Prometheus is unavailable")
	}
}

// TestVersionCleanupEvaluation_NoPrometheus_WithDeletionRules verifies that a
// CAV whose workloads DO have deletionRules is NOT deleted when Prometheus is
// unavailable, and that no requeue storm occurs.
func TestVersionCleanupEvaluation_NoPrometheus_WithDeletionRules(t *testing.T) {
	defer deregisterMetrics()

	c := setupTestControllerWithInitialResources(t, []string{
		"testdata/version-monitoring/ca-cleanup-enabled.yaml",
		"testdata/version-monitoring/cav-v1-deletion-rules.yaml",
		"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
		"testdata/version-monitoring/cat-provider-v2-ready.yaml",
	})

	o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
		address:                 "",
		evaluationInterval:      10 * time.Minute,
		acquireClientRetryDelay: time.Hour,
	})
	defer o.queue.ShutDown()

	item := NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}
	o.queue.Add(item)
	_ = c.processVersionCleanupQueueItem(context.TODO(), o)

	// No requeues expected (skipped, not an error).
	if o.queue.NumRequeues(item) != 0 {
		t.Errorf("expected zero requeues when CAV has deletion rules but Prometheus is unavailable, got %d", o.queue.NumRequeues(item))
	}

	// v1 must NOT have been deleted.
	_, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions("default").Get(context.TODO(), "test-cap-01-cav-v1", v1.GetOptions{})
	if err != nil {
		t.Errorf("expected version test-cap-01-cav-v1 to still exist when deletion rules cannot be evaluated: %v", err)
	}
}

// TestVersionCleanupEvaluation_PromUnreachable tests two evaluation cycles
// against an unreachable Prometheus server:
//   - a CAV WITH deletionRules must NOT be deleted
//   - a CAV WITHOUT deletionRules MUST be deleted
func TestVersionCleanupEvaluation_PromUnreachable(t *testing.T) {
	s, _ := getPromServer(true, []queryTestCase{}) // server always returns 503
	defer s.Close()

	t.Run("with deletion rules - not deleted", func(t *testing.T) {
		defer deregisterMetrics()

		c := setupTestControllerWithInitialResources(t, []string{
			"testdata/version-monitoring/ca-cleanup-enabled.yaml",
			"testdata/version-monitoring/cav-v1-deletion-rules.yaml",
			"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			"testdata/version-monitoring/cat-provider-v2-ready.yaml",
		})

		o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
			address:                 s.URL,
			evaluationInterval:      10 * time.Minute,
			acquireClientRetryDelay: time.Millisecond, // short so the first probe is attempted
		})
		defer o.queue.ShutDown()

		item := NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}
		o.queue.Add(item)
		_ = c.processVersionCleanupQueueItem(context.TODO(), o)

		if o.queue.NumRequeues(item) != 0 {
			t.Errorf("expected zero requeues for CAV with deletion rules when Prometheus is unreachable, got %d", o.queue.NumRequeues(item))
		}

		_, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions("default").Get(context.TODO(), "test-cap-01-cav-v1", v1.GetOptions{})
		if err != nil {
			t.Errorf("expected version test-cap-01-cav-v1 to still exist: %v", err)
		}
	})

	t.Run("without deletion rules - deleted", func(t *testing.T) {
		defer deregisterMetrics()

		c := setupTestControllerWithInitialResources(t, []string{
			"testdata/version-monitoring/ca-cleanup-enabled.yaml",
			"testdata/version-monitoring/cav-v1-no-deletion-rules.yaml",
			"testdata/version-monitoring/cav-v2-deletion-rules.yaml",
			"testdata/version-monitoring/cat-provider-v2-ready.yaml",
		})

		o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
			address:                 s.URL,
			evaluationInterval:      10 * time.Minute,
			acquireClientRetryDelay: time.Millisecond,
		})
		defer o.queue.ShutDown()

		item := NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}
		o.queue.Add(item)
		_ = c.processVersionCleanupQueueItem(context.TODO(), o)

		if o.queue.NumRequeues(item) != 0 {
			t.Errorf("expected zero requeues for CAV without deletion rules, got %d", o.queue.NumRequeues(item))
		}

		_, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions("default").Get(context.TODO(), "test-cap-01-cav-v1", v1.GetOptions{})
		if err == nil || !errors.IsNotFound(err) {
			t.Errorf("expected version test-cap-01-cav-v1 to be deleted when it has no deletion rules")
		}
	})
}

// TestVersionCleanupEvaluation_RuntimeInfoRateLimited verifies that the
// cachedPromClientProvider issues at most one runtimeinfo probe per
// acquireClientRetryDelay window. Two back-to-back Get() calls should only
// result in a single HTTP hit on the mock server.
func TestVersionCleanupEvaluation_RuntimeInfoRateLimited(t *testing.T) {
	s, _, hits := getPromServerWithCounter(true, []queryTestCase{}) // server always returns 503
	defer s.Close()

	// Use a generous retry delay so that the second immediate call is still
	// within the rate-limit window.
	o := initializeVersionCleanupOrchestrator(context.TODO(), &monitoringEnv{
		address:                 s.URL,
		evaluationInterval:      10 * time.Minute,
		acquireClientRetryDelay: 5 * time.Second,
	})
	defer o.queue.ShutDown()

	ctx := context.TODO()

	// First call: triggers a probe (lastProbeAt is zero).
	api1, ok1 := o.clientProvider.Get(ctx)
	if ok1 || api1 != nil {
		t.Errorf("expected first Get() to report unavailable (server returns 503)")
	}

	// Second call: must be rate-limited; no additional HTTP request should be made.
	api2, ok2 := o.clientProvider.Get(ctx)
	if ok2 || api2 != nil {
		t.Errorf("expected second Get() to report unavailable")
	}

	// Only one runtimeinfo probe must have hit the server.
	if hits.Load() > 1 {
		t.Errorf("expected at most 1 runtimeinfo probe, got %d", hits.Load())
	}
}
