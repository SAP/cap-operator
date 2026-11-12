//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// defaultTimeout is how long a test waits for the controller to converge on an
	// expected state. Reconciliation is asynchronous and event/resync driven.
	defaultTimeout = 30 * time.Second
	// pollInterval is how often expected-state assertions re-check the API server.
	pollInterval = 250 * time.Millisecond
)

// testContext returns a context scoped to the test, derived from the controller's
// context so that it is cancelled during suite teardown.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(env.controllerCtx)
	t.Cleanup(cancel)
	return ctx
}

// newNamespace creates a uniquely-named namespace for an individual test and registers
// a best-effort cleanup. Unique namespaces keep tests isolated from one another; note
// that envtest runs no namespace/GC controller, so a deleted namespace lingers in
// Terminating state - this is harmless because names are never reused.
func newNamespace(t *testing.T) string {
	t.Helper()
	ctx := testContext(t)
	name := fmt.Sprintf("itest-%s", rand.String(8))
	_, err := env.kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not create namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		// Best-effort; use a fresh context as the test context may already be cancelled.
		_ = env.kubeClient.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	return name
}

// eventually polls condition until it returns true or the timeout elapses. The last
// error/description returned by condition is included in the failure message so tests
// explain *why* the expected state was never reached.
func eventually(t *testing.T, condition func(ctx context.Context) (done bool, reason string, err error)) {
	t.Helper()
	ctx := testContext(t)
	var lastReason string
	var lastErr error
	waitErr := wait.PollUntilContextTimeout(ctx, pollInterval, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		done, reason, err := condition(ctx)
		lastReason, lastErr = reason, err
		// Transient errors (e.g. not-found while the controller is still working) do
		// not abort the poll; only a true result ends it.
		return done, nil
	})
	if waitErr != nil {
		t.Fatalf("condition not met within %s: reason=%q lastErr=%v", defaultTimeout, lastReason, lastErr)
	}
}

// markDeploymentReady patches a Deployment's status so the controller treats it as
// available. envtest runs no kubelet, so workload Deployments never become ready on
// their own; tests stub the status to drive reconciliation past "WaitingForWorkloads".
func markDeploymentReady(t *testing.T, ns, name string) {
	t.Helper()
	ctx := testContext(t)
	dep, err := env.kubeClient.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("could not get deployment %s/%s: %v", ns, name, err)
	}
	replicas := int32(1)
	if dep.Spec.Replicas != nil {
		replicas = *dep.Spec.Replicas
	}
	dep.Status.ObservedGeneration = dep.Generation
	dep.Status.Replicas = replicas
	dep.Status.ReadyReplicas = replicas
	dep.Status.AvailableReplicas = replicas
	dep.Status.UpdatedReplicas = replicas
	dep.Status.Conditions = []appsv1.DeploymentCondition{{
		Type:   appsv1.DeploymentAvailable,
		Status: corev1.ConditionTrue,
		Reason: "MinimumReplicasAvailable",
	}}
	if _, err := env.kubeClient.AppsV1().Deployments(ns).UpdateStatus(ctx, dep, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("could not update status of deployment %s/%s: %v", ns, name, err)
	}
}

// markJobComplete patches a Job's status so the controller treats it as succeeded.
// As with Deployments, envtest never actually runs the Job's pods.
func markJobComplete(t *testing.T, ns, name string) {
	t.Helper()
	ctx := testContext(t)
	job, err := env.kubeClient.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("could not get job %s/%s: %v", ns, name, err)
	}
	now := metav1.Now()
	job.Status.Succeeded = 1
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now
	// Kubernetes >= 1.33 requires the SuccessCriteriaMet condition to be set to True
	// before (or together with) the Complete condition.
	job.Status.Conditions = []batchv1.JobCondition{
		{
			Type:               batchv1.JobSuccessCriteriaMet,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: now,
			Reason:             "CompletionsReached",
		},
		{
			Type:               batchv1.JobComplete,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: now,
			Reason:             "CompletionsReached",
		},
	}
	if _, err := env.kubeClient.BatchV1().Jobs(ns).UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("could not update status of job %s/%s: %v", ns, name, err)
	}
}

// isNotFound is a small convenience wrapper used by assertions.
func isNotFound(err error) bool { return apierrors.IsNotFound(err) }
