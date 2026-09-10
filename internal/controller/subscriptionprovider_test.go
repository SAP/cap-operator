/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	copfake "github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// makeTestCA returns a minimal CAPApplication for subscriptionprovider unit tests.
func makeTestCA(name string, services []v1alpha1.ServiceInfo) *v1alpha1.CAPApplication {
	return &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       "test-ca-uid",
		},
		Spec: v1alpha1.CAPApplicationSpec{
			BTPAppName:           "test-btpapp",
			ProviderSubaccountId: "test-provider-id",
			BTP: v1alpha1.BTP{
				Services: services,
			},
		},
	}
}

// addCredentialSecret adds a legacy-format secret to the fake kube client tracker.
func addCredentialSecret(c *Controller, name string, credentials map[string]any) {
	credJSON, _ := json.Marshal(credentials)
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data:       map[string][]byte{"credentials": credJSON},
	})
}

// addExistingSubPro adds a SubscriptionProvider to both the fake crd tracker and the informer index.
func addExistingSubPro(c *Controller, sp *v1alpha1.SubscriptionProvider) {
	c.crdClient.(*copfake.Clientset).Tracker().Add(sp)
	c.crdInformerFactory.Sme().V1alpha1().SubscriptionProviders().Informer().GetIndexer().Add(sp)
}

// getTrackedSubPro fetches a SubscriptionProvider from the fake crd client tracker.
func getTrackedSubPro(c *Controller, name string) (*v1alpha1.SubscriptionProvider, error) {
	obj, err := c.crdClient.(*copfake.Clientset).Tracker().Get(
		v1alpha1.SchemeGroupVersion.WithResource("subscriptionproviders"),
		"default", name)
	if err != nil {
		return nil, err
	}
	return obj.(*v1alpha1.SubscriptionProvider), nil
}

// countSubProActions counts crd client actions of the given verb on subscriptionproviders.
func countSubProActions(c *Controller, verb string) int {
	n := 0
	for _, a := range c.crdClient.(*copfake.Clientset).Actions() {
		if a.GetVerb() == verb && a.GetResource().Resource == "subscriptionproviders" {
			n++
		}
	}
	return n
}

// TestResolveSubscriptionProvider_ServicesOnly verifies no SubscriptionProvider is created when CA is services-only.
func TestResolveSubscriptionProvider_ServicesOnly(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", nil)
	servicesOnly := true
	ca.Status.ServicesOnly = &servicesOnly

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := getTrackedSubPro(c, "test-ca"); err == nil {
		t.Error("expected no SubscriptionProvider to be created for services-only CA")
	}
}

// TestResolveSubscriptionProvider_SecretNotFound verifies an error is returned when a referenced service secret is missing.
func TestResolveSubscriptionProvider_SecretNotFound(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "missing-secret"},
	})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err == nil {
		t.Error("expected error when service secret is missing")
	}
}

// TestResolveSubscriptionProvider_NoDependencies verifies SubscriptionProvider is created with empty dependencies
// when the only service (xsuaa) does not qualify as a subscription dependency.
func TestResolveSubscriptionProvider_NoDependencies(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret"},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}
	if sp.Spec.Dependencies != "" {
		t.Errorf("expected empty dependencies, got: %s", sp.Spec.Dependencies)
	}
	if sp.Spec.SubscriptionInfo.Type != "" {
		t.Errorf("expected empty subscriptionInfo.type, got: %s", sp.Spec.SubscriptionInfo.Type)
	}
}

// TestResolveSubscriptionProvider_SaaSRegistryDependency verifies the saas-registry service is included
// as an xsappname dependency when saasregistryenabled=true in its credentials.
func TestResolveSubscriptionProvider_SaaSRegistryDependency(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret"},
		{Name: "saas-svc", Class: "saas-registry", Secret: "saas-secret"},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})
	addCredentialSecret(c, "saas-secret", map[string]any{"xsappname": "test-saas!b2", "saasregistryenabled": true})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}
	if want := `[{"xsappname":"test-saas!b2"}]`; sp.Spec.Dependencies != want {
		t.Errorf("expected dependencies %s, got: %s", want, sp.Spec.Dependencies)
	}
	if sp.Spec.SubscriptionInfo.Type != "saas-registry" {
		t.Errorf("expected subscriptionInfo.type saas-registry, got: %s", sp.Spec.SubscriptionInfo.Type)
	}
	if sp.Spec.SubscriptionInfo.SubscriptionSecret != "saas-secret" {
		t.Errorf("expected subscriptionSecret saas-secret, got: %s", sp.Spec.SubscriptionInfo.SubscriptionSecret)
	}
	if sp.Spec.SubscriptionInfo.AuthSecret != "xsuaa-secret" {
		t.Errorf("expected authSecret xsuaa-secret, got: %s", sp.Spec.SubscriptionInfo.AuthSecret)
	}
}

// TestResolveSubscriptionProvider_DestinationDependency verifies the destination service is included
// as an appName/appId special dependency.
func TestResolveSubscriptionProvider_DestinationDependency(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "dest-svc", Class: "destination", Secret: "dest-secret"},
	})
	addCredentialSecret(c, "dest-secret", map[string]any{"xsappname": "test-dest!b3"})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}
	if want := `[{"appId":"test-dest!b3","appName":"destination"}]`; sp.Spec.Dependencies != want {
		t.Errorf("expected dependencies %s, got: %s", want, sp.Spec.Dependencies)
	}
}

// TestResolveSubscriptionProvider_MixedDependencies verifies that only qualifying services are included:
// xsuaa (not a dep), saas-registry (dep via saasregistryenabled), destination (special dep), service-manager (not a dep).
func TestResolveSubscriptionProvider_MixedDependencies(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret"},
		{Name: "saas-svc", Class: "saas-registry", Secret: "saas-secret"},
		{Name: "dest-svc", Class: "destination", Secret: "dest-secret"},
		{Name: "sm-svc", Class: "service-manager", Secret: "sm-secret"},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})
	addCredentialSecret(c, "saas-secret", map[string]any{"xsappname": "test-saas!b2", "saasregistryenabled": true})
	addCredentialSecret(c, "dest-secret", map[string]any{"xsappname": "test-dest!b3"})
	addCredentialSecret(c, "sm-secret", map[string]any{"xsappname": "test-sm!b4"})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}
	want := `[{"xsappname":"test-saas!b2"},{"appId":"test-dest!b3","appName":"destination"}]`
	if sp.Spec.Dependencies != want {
		t.Errorf("expected dependencies %s, got: %s", want, sp.Spec.Dependencies)
	}
}

// TestResolveSubscriptionProvider_AlwaysDependency verifies that a service with SubscriptionDependencyAlways
// is always included regardless of credential content.
func TestResolveSubscriptionProvider_AlwaysDependency(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	always := v1alpha1.SubscriptionDependencyAlways
	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret", SubscriptionDependency: &always},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}
	if want := `[{"xsappname":"test-xsuaa!b1"}]`; sp.Spec.Dependencies != want {
		t.Errorf("expected dependencies %s, got: %s", want, sp.Spec.Dependencies)
	}
}

// TestResolveSubscriptionProvider_UpdateWhenChanged verifies that an existing SubscriptionProvider is updated
// when its spec hash differs from the current computed value.
func TestResolveSubscriptionProvider_UpdateWhenChanged(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	existing := &v1alpha1.SubscriptionProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ca",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationResourceHash: "stale-hash",
			},
		},
	}
	addExistingSubPro(c, existing)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret"},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})

	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates := countSubProActions(c, "update"); updates != 1 {
		t.Errorf("expected 1 update action, got %d", updates)
	}
}

// TestResolveSubscriptionProvider_NoUpdateWhenUnchanged verifies that an existing SubscriptionProvider is not
// updated when its hash matches the current computed value.
func TestResolveSubscriptionProvider_NoUpdateWhenUnchanged(t *testing.T) {
	defer deregisterMetrics()
	c := initializeControllerForReconciliationTests(t, nil, nil)

	ca := makeTestCA("test-ca", []v1alpha1.ServiceInfo{
		{Name: "xsuaa-svc", Class: "xsuaa", Secret: "xsuaa-secret"},
	})
	addCredentialSecret(c, "xsuaa-secret", map[string]any{"xsappname": "test-xsuaa!b1"})

	// First call creates the SubscriptionProvider with the correct hash annotation.
	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}
	sp, err := getTrackedSubPro(c, "test-ca")
	if err != nil {
		t.Fatalf("expected SubscriptionProvider to be created: %v", err)
	}

	// Add the created SubPro to the informer so the second call finds it.
	c.crdInformerFactory.Sme().V1alpha1().SubscriptionProviders().Informer().GetIndexer().Add(sp)

	// Second call with unchanged CA must not trigger an update.
	if err := c.resolveSubscriptionProvider(context.TODO(), ca); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if updates := countSubProActions(c, "update"); updates != 0 {
		t.Errorf("expected no update actions, got %d", updates)
	}
}
