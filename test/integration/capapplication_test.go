//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"slices"
	"testing"

	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCAPApplicationReconciliation verifies that, once its BTP secrets exist, a
// CAPApplication with no ready CAPApplicationVersion is picked up by the controller,
// which adds the finalizer and parks the resource in Processing (waiting for a version).
func TestCAPApplicationReconciliation(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	app := newCAPApplication(ns, "test-cap-01")
	for svc, secret := range btpSecretNames(app.Name) {
		if _, err := env.kubeClient.CoreV1().Secrets(ns).Create(ctx, newBTPSecret(ns, secret), metav1.CreateOptions{}); err != nil {
			t.Fatalf("create secret %s (for %s): %v", secret, svc, err)
		}
	}

	if _, err := env.copClient.SmeV1alpha2().CAPApplications(ns).Create(ctx, app, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create capapplication: %v", err)
	}

	eventually(t, func(ctx context.Context) (bool, string, error) {
		got, err := env.copClient.SmeV1alpha2().CAPApplications(ns).Get(ctx, app.Name, metav1.GetOptions{})
		if err != nil {
			return false, "getting capapplication", err
		}
		if !slices.Contains(got.Finalizers, controller.FinalizerCAPApplication) {
			return false, "finalizer not yet added", nil
		}
		if got.Status.State != v1alpha2.CAPApplicationStateProcessing {
			return false, "state is " + string(got.Status.State) + ", want Processing", nil
		}
		return true, "", nil
	})
}

// TestCAPApplicationMissingSecrets verifies that a CAPApplication whose BTP secrets are
// absent does not get stuck in an unexpected state - it stays out of Consistent and the
// controller keeps it in Processing while waiting for the secrets.
func TestCAPApplicationMissingSecrets(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	app := newCAPApplication(ns, "test-cap-02")
	if _, err := env.copClient.SmeV1alpha2().CAPApplications(ns).Create(ctx, app, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create capapplication: %v", err)
	}

	eventually(t, func(ctx context.Context) (bool, string, error) {
		got, err := env.copClient.SmeV1alpha2().CAPApplications(ns).Get(ctx, app.Name, metav1.GetOptions{})
		if err != nil {
			return false, "getting capapplication", err
		}
		if got.Status.State == v1alpha2.CAPApplicationStateConsistent {
			return false, "unexpectedly Consistent without secrets", nil
		}
		if !slices.Contains(got.Finalizers, controller.FinalizerCAPApplication) {
			return false, "finalizer not yet added", nil
		}
		return got.Status.State == v1alpha2.CAPApplicationStateProcessing, "state is " + string(got.Status.State), nil
	})
}
