/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
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
	"sync"
	"testing"
	"time"

	prommodel "github.com/prometheus/common/model"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

func setupWithInitialResources(t *testing.T, initialResources []string) *Controller {
	c := initializeControllerForReconciliationTests(t, []ResourceAction{})
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
			c := setupWithInitialResources(t, tc.resources)
			orc := &cleanupOrchestrator{queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[NamespacedResourceKey]())}
			defer orc.queue.ShutDown()
			err := c.queueVersionsForCleanupEvaluation(context.TODO(), orc)
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

func Test_initializeVersionCleanupOrchestrator(t *testing.T) {
	tests := []struct {
		name              string
		serverUnavailable bool
	}{
		{
			name:              "initialize cleanup orchestrator and verify connection",
			serverUnavailable: false,
		},
		{
			name:              "ensure retry of cleanup orchestrator initialization",
			serverUnavailable: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := getPromServer(tt.serverUnavailable, []queryTestCase{})
			defer s.Close()
			var o *cleanupOrchestrator
			testCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			go func() {
				o = initializeVersionCleanupOrchestrator(testCtx, &monitoringEnv{address: s.URL, evaluationInterval: 2 * time.Minute, acquireClientRetryDelay: 30 * time.Second})
				if o != nil {
					cancel()
				}
			}()
			<-testCtx.Done()
			if tt.serverUnavailable {
				if testCtx.Err() == nil || testCtx.Err() != context.DeadlineExceeded {
					t.Error("expected to exceed test context deadline")
				}
			} else {
				if o == nil {
					t.Errorf("could not initialize prometheus client")
				}
				defer o.queue.ShutDown()
			}

		})
	}
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
			c := setupWithInitialResources(t, tt.startResources)
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
