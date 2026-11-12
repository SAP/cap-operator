//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDomainReconciliation verifies that, given a Domain and a matching ingress
// gateway, the controller: (1) adds its finalizer, (2) resolves the ingress and sets a
// status state, and (3) creates the derived Istio Gateway. The TLS certificate cannot
// become Ready in envtest (no cert-manager controller runs), so the Domain is expected
// to settle in a non-terminal state rather than Ready.
func TestDomainReconciliation(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	// Ingress gateway discovery objects (pod + LoadBalancer service + endpoint slice).
	infra := newIngressGatewayInfra(ns)
	if _, err := env.kubeClient.CoreV1().Pods(ns).Create(ctx, infra.pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ingress pod: %v", err)
	}
	if _, err := env.kubeClient.CoreV1().Services(ns).Create(ctx, infra.service, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ingress service: %v", err)
	}
	if _, err := env.kubeClient.DiscoveryV1().EndpointSlices(ns).Create(ctx, infra.endpointSlice, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ingress endpointslice: %v", err)
	}

	dom := newDomain(ns, "test-cap-01-primary", fmt.Sprintf("app.%s.example.local", ns), infra.selector)
	if _, err := env.copClient.SmeV1alpha2().Domains(ns).Create(ctx, dom, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	// (1) + (2): finalizer added and a status state reached.
	eventually(t, func(ctx context.Context) (bool, string, error) {
		got, err := env.copClient.SmeV1alpha2().Domains(ns).Get(ctx, dom.Name, metav1.GetOptions{})
		if err != nil {
			return false, "getting domain", err
		}
		if !slices.Contains(got.Finalizers, controller.FinalizerDomain) {
			return false, "finalizer not yet added", nil
		}
		if got.Status.State == "" {
			return false, "status state not yet set", nil
		}
		return true, "", nil
	})

	// (3): the derived Istio Gateway is created in the namespace.
	eventually(t, func(ctx context.Context) (bool, string, error) {
		gws, err := env.istioClient.NetworkingV1().Gateways(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, "listing gateways", err
		}
		if len(gws.Items) == 0 {
			return false, "no gateway created yet", nil
		}
		return true, "", nil
	})

	// Sanity: the state should be Processing (certificate never becomes Ready here).
	got, err := env.copClient.SmeV1alpha2().Domains(ns).Get(ctx, dom.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}
	if got.Status.State == v1alpha2.DomainStateError {
		t.Errorf("domain unexpectedly in Error state: %+v", got.Status.Conditions)
	}
}
