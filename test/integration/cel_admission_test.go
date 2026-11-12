//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"encoding/json"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// These tests exercise CRD admission (CEL x-kubernetes-validations) through the REAL
// kube-apiserver, which the in-process CEL unit tests in
// pkg/apis/sme.sap.com/v1alpha2/cel_test.go cannot do. They complement - not replace -
// those unit tests: the unit tests assert the rules and their messages in isolation;
// these assert the rules as the apiserver actually applies them on create/update.
//
// All CAPApplicationVersions here are created WITHOUT a parent CAPApplication so the
// controller errors out of reconciliation before mutating them (see
// prepareCAPApplicationVersion -> getCachedCAPApplication). That keeps the admission
// assertions deterministic (no concurrent metadata churn).

var capAppVersionGVR = v1alpha2.SchemeGroupVersion.WithResource("capapplicationversions")

// TestCAVResourceQuantityDriftAdmission reproduces, against the real apiserver, the bug
// that forced the operator to patch metadata instead of issuing a full-object Update
// during reconcile.
//
// When a CAPApplicationVersion is applied with an integer workload resource quantity
// (e.g. `cpu: 1`, as kubectl/Helm would send it), the apiserver stores it as an integer
// because the field is x-kubernetes-int-or-string. The typed Go client, however, always
// serializes resource.Quantity to a string ("1"). A full-object Update therefore changes
// the stored spec representation (1 -> "1"), and the spec's generated `self == oldSelf`
// immutability rule rejects it. The operator's metadata-only patch leaves the spec
// untouched and is accepted.
func TestCAVResourceQuantityDriftAdmission(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	dyn, err := dynamic.NewForConfig(env.cfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}

	cavName := "cav-quantity-drift"

	// Build a schema-valid CAV with an integer cpu request. We start from the typed
	// fixture (guaranteed schema-valid), round-trip it through JSON (where the Quantity
	// becomes the string "1"), then override cpu to the integer 1 - exactly the stored
	// shape that `kubectl apply` of `cpu: 1` produces.
	cav := newCAPApplicationVersion(ns, cavName, "no-such-app")
	cav.Spec.Workloads[0].DeploymentDefinition.Resources = &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
	}
	raw, err := json.Marshal(cav)
	if err != nil {
		t.Fatalf("marshal cav: %v", err)
	}
	obj := map[string]interface{}{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal cav: %v", err)
	}
	obj["apiVersion"] = v1alpha2.SchemeGroupVersion.String()
	obj["kind"] = v1alpha2.CAPApplicationVersionKind
	setWorkloadCPU(t, obj, int64(1))

	if _, err := dyn.Resource(capAppVersionGVR).Namespace(ns).Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create cav with integer cpu quantity: %v", err)
	}

	// Sanity: the stored quantity really is numeric, not the string "1" - otherwise there
	// is no int->string drift to reproduce.
	stored, err := dyn.Resource(capAppVersionGVR).Namespace(ns).Get(ctx, cavName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get stored cav: %v", err)
	}
	if got := storedWorkloadCPU(t, stored.Object); isStringValue(got) {
		t.Fatalf("expected stored cpu to be a numeric quantity, got string %v - cannot reproduce drift", got)
	}

	// A full-object Update via the typed client re-serializes the Quantity to "1" and is
	// rejected by the spec immutability rule - this is the bug.
	typed, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Get(ctx, cavName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("typed get cav: %v", err)
	}
	if typed.Labels == nil {
		typed.Labels = map[string]string{}
	}
	typed.Labels["example.test/touched"] = "true" // only metadata changes; spec is resent unchanged in intent
	_, updErr := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Update(ctx, typed, metav1.UpdateOptions{})
	if updErr == nil {
		t.Fatalf("expected full-object Update to be rejected by spec immutability rule, but it succeeded")
	}
	if !apierrors.IsInvalid(updErr) {
		t.Fatalf("expected an Invalid (admission) error from the full Update, got: %v", updErr)
	}
	t.Logf("full Update correctly rejected: %v", updErr)

	// The operator's actual workaround - a metadata-only merge patch that never resends
	// the spec - is accepted.
	patch := []byte(`{"metadata":{"labels":{"example.test/touched":"true"}}}`)
	if _, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Patch(ctx, cavName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		t.Fatalf("metadata-only merge patch should be accepted, got: %v", err)
	}
}

// TestCAVSpecImmutabilityAdmission is a basic CEL admission test: the apiserver rejects a
// change to the (immutable) CAPApplicationVersion spec on update.
func TestCAVSpecImmutabilityAdmission(t *testing.T) {
	ns := newNamespace(t)
	ctx := testContext(t)

	cavName := "cav-spec-immutable"
	cav := newCAPApplicationVersion(ns, cavName, "no-such-app")
	if _, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Create(ctx, cav, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create cav: %v", err)
	}

	got, err := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Get(ctx, cavName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cav: %v", err)
	}
	got.Spec.Version = "2.0.0" // mutating an immutable spec field
	_, updErr := env.copClient.SmeV1alpha2().CAPApplicationVersions(ns).Update(ctx, got, metav1.UpdateOptions{})
	if updErr == nil {
		t.Fatalf("expected spec change to be rejected, but update succeeded")
	}
	if !apierrors.IsInvalid(updErr) {
		t.Fatalf("expected an Invalid (admission) error, got: %v", updErr)
	}
}

// setWorkloadCPU sets spec.workloads[0].deploymentDefinition.resources.requests.cpu on an
// unstructured CAV object.
func setWorkloadCPU(t *testing.T, obj map[string]interface{}, cpu interface{}) {
	t.Helper()
	requests := nestedWorkloadRequests(t, obj)
	requests["cpu"] = cpu
}

// storedWorkloadCPU reads the same cpu field back from an unstructured CAV object.
func storedWorkloadCPU(t *testing.T, obj map[string]interface{}) interface{} {
	t.Helper()
	return nestedWorkloadRequests(t, obj)["cpu"]
}

func nestedWorkloadRequests(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	spec, ok := obj["spec"].(map[string]interface{})
	if !ok {
		t.Fatalf("spec missing or wrong type")
	}
	workloads, ok := spec["workloads"].([]interface{})
	if !ok || len(workloads) == 0 {
		t.Fatalf("workloads missing or empty")
	}
	wl, ok := workloads[0].(map[string]interface{})
	if !ok {
		t.Fatalf("workload[0] wrong type")
	}
	dd, ok := wl["deploymentDefinition"].(map[string]interface{})
	if !ok {
		t.Fatalf("deploymentDefinition missing")
	}
	res, ok := dd["resources"].(map[string]interface{})
	if !ok {
		t.Fatalf("resources missing")
	}
	requests, ok := res["requests"].(map[string]interface{})
	if !ok {
		t.Fatalf("resources.requests missing")
	}
	return requests
}

func isStringValue(v interface{}) bool {
	_, ok := v.(string)
	return ok
}
