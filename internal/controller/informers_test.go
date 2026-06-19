/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"testing"
	"time"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

// secretHandlerFixture builds a controller with the given CAPApplications pre-loaded
// and attaches a real rolloutManager so the handler can enqueue into it.
func secretHandlerFixture(cas []*v1alpha1.CAPApplication) *Controller {
	c := getTestController(testResources{cas: cas})
	c.rolloutManager = newRolloutManager(c)
	return c
}

// pendingForNamespace reads the accumulated pending secrets without consuming them.
func pendingForNamespace(m *rolloutManager, ns string) map[string]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingSecrets[ns]
}

func secretV(name, ns, rv string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, ResourceVersion: rv},
	}
}

var expectedResult = false

type dummyType struct {
	workqueue.TypedRateLimitingInterface[QueueItem]
}

func (q *dummyType) Add(_ QueueItem) {
	expectedResult = true
}

func (q *dummyType) AddAfter(_ QueueItem, _ time.Duration) {
	expectedResult = true
}

func TestController_initializeInformers(t *testing.T) {
	tests := []struct {
		name            string
		expectedResult  bool
		ownerOnlyCheck  bool
		invalidOwnerRef bool
		res             int
		itemName        string
		itemNamespace   string
	}{
		{
			name:           "Test enqueueModifiedResource (ResourceCAPApplication)",
			res:            ResourceCAPApplication,
			expectedResult: true,
			itemName:       "test-ca",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (ResourceCAPApplicationVersion)",
			res:            ResourceCAPApplicationVersion,
			expectedResult: true,
			itemName:       "test-cav",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (ResourceCertificate) valid owner",
			res:            ResourceCertificate,
			ownerOnlyCheck: true,
			expectedResult: true,
			itemName:       "test-cert",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:            "Test enqueueModifiedResource (ResourceCertificate) invalid owner",
			res:             ResourceCertificate,
			ownerOnlyCheck:  true,
			expectedResult:  false,
			invalidOwnerRef: true,
			itemName:        "test-cert",
			itemNamespace:   corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (unknown resource)",
			res:            99,
			expectedResult: false,
			itemName:       "test-unknown-resource",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (invalid queue key)",
			res:            999,
			expectedResult: false,
			itemName:       "test-unknown-key",
			itemNamespace:  corev1.NamespaceDefault,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Deregister metrics
			defer deregisterMetrics()

			c := getTestController(testResources{})
			expectedResult = false

			queues := map[int]workqueue.TypedRateLimitingInterface[QueueItem]{
				ResourceCAPApplication:        &dummyType{},
				ResourceCAPApplicationVersion: &dummyType{},
				ResourceCAPTenant:             &dummyType{},
				ResourceCAPTenantOperation:    &dummyType{},
				ResourceDomain:                &dummyType{},
				ResourceClusterDomain:         &dummyType{},
			}

			testC := &Controller{
				kubeClient:                  c.kubeClient,
				crdClient:                   c.crdClient,
				istioClient:                 c.istioClient,
				gardenerCertificateClient:   c.gardenerCertificateClient,
				gardenerDNSClient:           c.gardenerDNSClient,
				kubeInformerFactory:         c.kubeInformerFactory,
				crdInformerFactory:          c.crdInformerFactory,
				istioInformerFactory:        c.istioInformerFactory,
				gardenerCertInformerFactory: c.gardenerCertInformerFactory,
				gardenerDNSInformerFactory:  c.gardenerDNSInformerFactory,
				queues:                      queues,
			}

			testC.initializeInformers()
			var res, oldRes any
			switch tt.res {
			case ResourceCAPApplication:
				res = createCaCRO(tt.itemName, false)
			case ResourceCAPApplicationVersion:
				ca := createCaCRO(tt.itemName, false)
				cav := createCavCRO(tt.itemName, v1alpha1.CAPApplicationVersionStateReady, defaultVersion)
				cav.ObjectMeta.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind))}
				res = cav
			case ResourceCertificate:
				// set label on a pod to simulate certificate in a different namespace
				cert := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tt.itemName, Annotations: map[string]string{
					AnnotationOwnerIdentifier: KindMap[ResourceDomain] + "." + tt.itemNamespace + "." + tt.itemName,
				}, Labels: map[string]string{
					LabelOwnerIdentifierHash: sha1Sum(KindMap[ResourceDomain], tt.itemNamespace, tt.itemName),
				}}}
				// Invalid label
				if tt.invalidOwnerRef {
					cert.Annotations[AnnotationOwnerIdentifier] = tt.itemNamespace + "." + tt.itemName
					cert.Labels[LabelOwnerIdentifierHash] = sha1Sum(tt.itemNamespace, tt.itemName)
				}
				oldRes = cert
				newCert := cert.DeepCopy()
				newCert.SetResourceVersion("2")
				res = newCert
			case 999:
				res = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tt.itemName}}
			}
			// Add/delete
			if !tt.ownerOnlyCheck {
				testC.enqueueModifiedResource(tt.res, res, nil)
				if expectedResult != tt.expectedResult {
					t.Error("Unexpected result", expectedResult)
				}
			}
			// Update
			testC.enqueueModifiedResource(tt.res, res, oldRes)
			if expectedResult != tt.expectedResult {
				t.Error("Unexpected result", expectedResult)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getSecretEventHandlerFuncs
// ---------------------------------------------------------------------------

// TestSecretHandler_SameResourceVersion verifies that an update where old and new
// have identical ResourceVersions is ignored (no enqueue).
func TestSecretHandler_SameResourceVersion(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	c := secretHandlerFixture([]*v1alpha1.CAPApplication{ca})

	handler := c.getSecretEventHandlerFuncs()
	old := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "1")
	new := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "1") // same RV

	handler.UpdateFunc(old, new)

	if got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault); len(got) != 0 {
		t.Errorf("expected nothing enqueued for same ResourceVersion, got %v", got)
	}
}

// TestSecretHandler_InvalidObjects verifies that non-meta objects are silently ignored.
func TestSecretHandler_InvalidObjects(t *testing.T) {
	defer deregisterMetrics()
	c := secretHandlerFixture(nil)

	handler := c.getSecretEventHandlerFuncs()
	// plain strings cannot be accessed via meta.Accessor
	handler.UpdateFunc("not-a-k8s-object", "also-not-a-k8s-object")

	if got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault); len(got) != 0 {
		t.Errorf("expected nothing enqueued for non-meta objects, got %v", got)
	}
}

// TestSecretHandler_NoCAPApplicationsInNamespace verifies that when no
// CAPApplication exists in the secret's namespace, nothing is enqueued.
func TestSecretHandler_NoCAPApplicationsInNamespace(t *testing.T) {
	defer deregisterMetrics()
	c := secretHandlerFixture(nil) // no CAs

	handler := c.getSecretEventHandlerFuncs()
	old := secretV("some-secret", metav1.NamespaceDefault, "1")
	new := secretV("some-secret", metav1.NamespaceDefault, "2")

	handler.UpdateFunc(old, new)

	if got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault); len(got) != 0 {
		t.Errorf("expected nothing enqueued when no CAPApplications exist, got %v", got)
	}
}

// TestSecretHandler_AllCAsRolloutDisabled verifies that when every CAPApplication
// in the namespace has RolloutOnCredentialUpdate=false, nothing is enqueued.
func TestSecretHandler_AllCAsRolloutDisabled(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", false /* disabled */, btpServices())
	c := secretHandlerFixture([]*v1alpha1.CAPApplication{ca})

	handler := c.getSecretEventHandlerFuncs()
	old := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "1")
	new := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "2")

	handler.UpdateFunc(old, new)

	if got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault); len(got) != 0 {
		t.Errorf("expected nothing enqueued when all CAs have rollout disabled, got %v", got)
	}
}

// TestSecretHandler_OneCAWithRolloutEnabled verifies that a secret update enqueues
// exactly once when at least one CAPApplication in the namespace has
// RolloutOnCredentialUpdate=true, regardless of how many CAs exist.
func TestSecretHandler_OneCAWithRolloutEnabled(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	c := secretHandlerFixture([]*v1alpha1.CAPApplication{ca})

	handler := c.getSecretEventHandlerFuncs()
	old := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "1")
	new := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "2")

	handler.UpdateFunc(old, new)

	got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault)
	if len(got) != 1 {
		t.Fatalf("expected 1 pending secret, got %d: %v", len(got), got)
	}
	if _, ok := got["cap-cap-01-uaa-bind-cf"]; !ok {
		t.Errorf("expected secret name cap-cap-01-uaa-bind-cf to be pending, got %v", got)
	}
}

// TestSecretHandler_EnqueuesOnceWithMixedCAs verifies that even when one CA has
// rollout disabled and another has it enabled, the secret is enqueued exactly once
// (the handler breaks after the first CA that triggers the enqueue).
func TestSecretHandler_EnqueuesOnceWithMixedCAs(t *testing.T) {
	defer deregisterMetrics()
	caDisabled := buildCA("test-cap-disabled", false, btpServices())
	caEnabled := buildCA("test-cap-enabled", true, btpServices())
	c := secretHandlerFixture([]*v1alpha1.CAPApplication{caDisabled, caEnabled})

	handler := c.getSecretEventHandlerFuncs()
	old := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "1")
	new := secretV("cap-cap-01-uaa-bind-cf", metav1.NamespaceDefault, "2")

	handler.UpdateFunc(old, new)
	handler.UpdateFunc(old, new) // second update with same secret, different call

	got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault)
	// pendingSecrets is a set so duplicate enqueues for the same secret name are idempotent
	if len(got) != 1 {
		t.Fatalf("expected 1 pending secret entry, got %d: %v", len(got), got)
	}
}

// TestSecretHandler_OnlyUpdateFuncWired verifies that the Add and Delete handler
// slots are nil — the secret handler intentionally only reacts to updates.
func TestSecretHandler_OnlyUpdateFuncWired(t *testing.T) {
	defer deregisterMetrics()
	c := secretHandlerFixture(nil)
	handler := c.getSecretEventHandlerFuncs()

	if handler.AddFunc != nil {
		t.Error("expected AddFunc to be nil for secret handler")
	}
	if handler.DeleteFunc != nil {
		t.Error("expected DeleteFunc to be nil for secret handler")
	}
	if handler.UpdateFunc == nil {
		t.Error("expected UpdateFunc to be set for secret handler")
	}
}

// TestSecretHandler_MultipleDistinctSecrets verifies that several different secrets
// updated in the same namespace all accumulate in pendingSecrets as a set.
func TestSecretHandler_MultipleDistinctSecrets(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	c := secretHandlerFixture([]*v1alpha1.CAPApplication{ca})

	handler := c.getSecretEventHandlerFuncs()
	for i, name := range []string{"secret-a", "secret-b", "secret-c"} {
		rv := func(n int) string { return string(rune('0' + n)) }
		handler.UpdateFunc(secretV(name, metav1.NamespaceDefault, rv(i)), secretV(name, metav1.NamespaceDefault, rv(i+10)))
	}

	got := pendingForNamespace(c.rolloutManager, metav1.NamespaceDefault)
	if len(got) != 3 {
		t.Fatalf("expected 3 pending secrets, got %d: %v", len(got), got)
	}
}
