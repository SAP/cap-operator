//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCAPApplicationVersionReconciliation is the "dummy app" proof for the framework.
// It creates a CAPApplication and a CAPApplicationVersion and verifies that the
// controller:
//  1. creates the owned workloads (CAP server + app-router Deployments, content Job);
//  2. parks the version in Processing/WaitingForWorkloads while those workloads are not
//     ready (envtest runs no kubelet, so they never become ready on their own);
//  3. advances the version to Ready once the dependency statuses are stubbed, and in
//     turn drives the CAPApplication to Consistent.
func TestCAPApplicationVersionReconciliation(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	appName := "test-cap-01"
	app := newCAPApplication(ns, appName)
	for _, secret := range btpSecretNames(appName) {
		if _, err := env.kubeClient.CoreV1().Secrets(ns).Create(ctx, newBTPSecret(ns, secret), metav1.CreateOptions{}); err != nil {
			t.Fatalf("create secret %s: %v", secret, err)
		}
	}
	if _, err := env.copClient.SmeV1alpha2().CAPApplications(ns).Create(ctx, app, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create capapplication: %v", err)
	}

	cavName := appName + "-cav-v1"
	cav := newCAPApplicationVersion(ns, cavName, appName)
	if _, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Create(ctx, cav, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create capapplicationversion: %v", err)
	}

	// (1) owned workloads are created: the CAP server + app-router Deployments and the
	// content Job.
	eventually(t, func(ctx context.Context) (bool, string, error) {
		deps, err := env.kubeClient.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, "listing deployments", err
		}
		jobs, err := env.kubeClient.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, "listing jobs", err
		}
		if len(deps.Items) < 2 {
			return false, "fewer than 2 deployments created so far", nil
		}
		if len(jobs.Items) < 1 {
			return false, "content job not created yet", nil
		}
		return true, "", nil
	})

	// (2) while workloads are not ready, the version stays in Processing.
	cur, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Get(ctx, cavName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get capapplicationversion: %v", err)
	}
	if cur.Status.State == v1alpha2.CAPApplicationVersionStateReady {
		t.Fatalf("version reached Ready before workload statuses were stubbed")
	}

	// (3) stub the dependency statuses - mark every created Deployment available and
	// every Job complete - then expect the controller to drive the version to Ready.
	stubWorkloadStatuses(t, ns, cavName)

	eventually(t, func(ctx context.Context) (bool, string, error) {
		// Newly created workloads (e.g. created on a later reconcile) also need stubbing.
		stubWorkloadStatuses(t, ns, cavName)
		got, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Get(ctx, cavName, metav1.GetOptions{})
		if err != nil {
			return false, "getting capapplicationversion", err
		}
		if got.Status.State != v1alpha2.CAPApplicationVersionStateReady {
			return false, "state is " + string(got.Status.State) + ", want Ready", nil
		}
		return true, "", nil
	})

	// Once the version is Ready, the controller advances the CAPApplication to
	// provider-tenant provisioning and creates the provider CAPTenant. (Full
	// CAPApplication "Consistent" additionally requires the tenant to finish
	// provisioning, which is out of scope for this suite.)
	eventually(t, func(ctx context.Context) (bool, string, error) {
		tenants, err := env.copClient.SmeV1alpha2().CAPTenants(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, "listing captenants", err
		}
		if len(tenants.Items) == 0 {
			return false, "provider CAPTenant not created yet", nil
		}
		return true, "", nil
	})
}

// stubWorkloadStatuses marks all Deployments available and all Jobs complete in the
// namespace. It is idempotent and safe to call repeatedly as new workloads appear.
func stubWorkloadStatuses(t *testing.T, ns, cavName string) {
	t.Helper()
	ctx := testContext(t)

	deps, err := env.kubeClient.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	for i := range deps.Items {
		d := deps.Items[i]
		if !isReadyDeployment(d) {
			markDeploymentReady(t, ns, d.Name)
		}
	}

	jobs, err := env.kubeClient.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	for i := range jobs.Items {
		j := jobs.Items[i]
		if !isCompleteJob(j) {
			markJobComplete(t, ns, j.Name)
		}
	}
}

func isReadyDeployment(d appsv1.Deployment) bool {
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == "True" {
			return true
		}
	}
	return false
}

func isCompleteJob(j batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == "True" {
			return true
		}
	}
	return false
}
