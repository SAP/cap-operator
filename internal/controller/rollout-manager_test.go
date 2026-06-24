/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildCA creates a CAPApplication with the given services and the
// RolloutOnCredentialUpdate flag set to enabled.
func buildCA(name string, rolloutEnabled bool, services []v1alpha1.ServiceInfo) *v1alpha1.CAPApplication {
	return &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, btpApplicationName),
			},
		},
		Spec: v1alpha1.CAPApplicationSpec{
			GlobalAccountId:           globalAccountId,
			BTPAppName:                btpApplicationName,
			RolloutOnCredentialUpdate: rolloutEnabled,
			BTP: v1alpha1.BTP{
				Services: services,
			},
		},
	}
}

// buildReadyCAV creates a CAPApplicationVersion in Ready state with the given workloads.
func buildReadyCAV(name, caName string, workloads []v1alpha1.WorkloadDetails) *v1alpha1.CAPApplicationVersion {
	return &v1alpha1.CAPApplicationVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelOwnerIdentifierHash: sha1Sum(metav1.NamespaceDefault, caName),
			},
		},
		Spec: v1alpha1.CAPApplicationVersionSpec{
			CAPApplicationInstance: caName,
			Version:                "1.0.0",
			Workloads:              workloads,
		},
		Status: v1alpha1.CAPApplicationVersionStatus{
			GenericStatus: v1alpha1.GenericStatus{
				Conditions: []metav1.Condition{
					{Type: string(v1alpha1.ConditionTypeReady), Status: metav1.ConditionTrue},
				},
			},
			State: v1alpha1.CAPApplicationVersionStateReady,
		},
	}
}

// buildReadyTenant creates a CAPTenant in Ready state pointing to cavName.
func buildReadyTenant(name, caName, cavName string) *v1alpha1.CAPTenant {
	return &v1alpha1.CAPTenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, btpApplicationName),
				LabelTenantId:                     providerTenantId,
			},
		},
		Spec: v1alpha1.CAPTenantSpec{
			CAPApplicationInstance: caName,
			BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
				SubDomain: providerSubDomain,
				TenantId:  providerTenantId,
			},
		},
		Status: v1alpha1.CAPTenantStatus{
			State:                                v1alpha1.CAPTenantStateReady,
			CurrentCAPApplicationVersionInstance: cavName,
			GenericStatus: v1alpha1.GenericStatus{
				Conditions: []metav1.Condition{
					{Type: string(v1alpha1.ConditionTypeReady), Status: metav1.ConditionTrue},
				},
			},
		},
	}
}

// buildDeployment creates a minimal Deployment for a workload in the given CAV.
func buildDeployment(cavName, workloadName, namespace string) *appsv1.Deployment {
	deployName := getWorkloadName(cavName, workloadName)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "server", Image: "test://image", EnvFrom: []corev1.EnvFromSource{}},
					},
					InitContainers: []corev1.Container{},
				},
			},
		},
	}
}

// btpServices returns a reusable set of service definitions matching the common credential-secrets.
func btpServices() []v1alpha1.ServiceInfo {
	return []v1alpha1.ServiceInfo{
		{Class: "xsuaa", Name: "cap-uaa", Secret: "cap-cap-01-uaa-bind-cf"},
		{Class: "saas-registry", Name: "cap-saas-registry", Secret: "cap-cap-01-saas-bind-cf"},
		{Class: "service-manager", Name: "cap-service-manager", Secret: "cap-cap-01-svc-man-bind-cf"},
	}
}

// ---------------------------------------------------------------------------
// getRolloutDelay
// ---------------------------------------------------------------------------

func TestGetRolloutDelay_DefaultWhenUnset(t *testing.T) {
	t.Setenv(EnvRolloutDelay, "")
	if got := getRolloutDelay(); got != defaultRolloutDelay {
		t.Errorf("expected default %v, got %v", defaultRolloutDelay, got)
	}
}

func TestGetRolloutDelay_DefaultWhenEnvVarNotPresent(t *testing.T) {
	os.Unsetenv(EnvRolloutDelay)
	t.Cleanup(func() { os.Unsetenv(EnvRolloutDelay) })
	if got := getRolloutDelay(); got != defaultRolloutDelay {
		t.Errorf("expected default %v when env var absent, got %v", defaultRolloutDelay, got)
	}
}

func TestGetRolloutDelay_ValidDuration(t *testing.T) {
	t.Setenv(EnvRolloutDelay, "2m")
	if got := getRolloutDelay(); got != 2*time.Minute {
		t.Errorf("expected 2m, got %v", got)
	}
}

func TestGetRolloutDelay_InvalidDurationFallsBackToDefault(t *testing.T) {
	t.Setenv(EnvRolloutDelay, "not-a-duration")
	if got := getRolloutDelay(); got != defaultRolloutDelay {
		t.Errorf("expected default %v for invalid value, got %v", defaultRolloutDelay, got)
	}
}

func TestGetRolloutDelay_WhitespaceOnlyFallsBackToDefault(t *testing.T) {
	t.Setenv(EnvRolloutDelay, "   ")
	if got := getRolloutDelay(); got != defaultRolloutDelay {
		t.Errorf("expected default %v for whitespace-only value, got %v", defaultRolloutDelay, got)
	}
}

func TestGetRolloutDelay_BelowMinimumClamped(t *testing.T) {
	t.Setenv(EnvRolloutDelay, "5s")
	if got := getRolloutDelay(); got != minRolloutDelay {
		t.Errorf("expected minimum %v for below-minimum value, got %v", minRolloutDelay, got)
	}
}

// ---------------------------------------------------------------------------
// btpServicesForSecrets
// ---------------------------------------------------------------------------

func TestBtpServicesForSecrets_AllMatch(t *testing.T) {
	ca := buildCA("test-cap-01", true, btpServices())
	secrets := map[string]struct{}{
		"cap-cap-01-uaa-bind-cf":  {},
		"cap-cap-01-saas-bind-cf": {},
	}
	result := btpServicesForSecrets(ca, secrets)
	if len(result) != 2 {
		t.Fatalf("expected 2 matched services, got %d", len(result))
	}
	if _, ok := result["cap-uaa"]; !ok {
		t.Error("expected cap-uaa in result")
	}
	if _, ok := result["cap-saas-registry"]; !ok {
		t.Error("expected cap-saas-registry in result")
	}
}

func TestBtpServicesForSecrets_NoMatch(t *testing.T) {
	ca := buildCA("test-cap-01", true, btpServices())
	secrets := map[string]struct{}{
		"some-unrelated-secret": {},
	}
	result := btpServicesForSecrets(ca, secrets)
	if len(result) != 0 {
		t.Fatalf("expected 0 matched services, got %d", len(result))
	}
}

func TestBtpServicesForSecrets_EmptySecretSet(t *testing.T) {
	ca := buildCA("test-cap-01", true, btpServices())
	result := btpServicesForSecrets(ca, map[string]struct{}{})
	if len(result) != 0 {
		t.Fatalf("expected 0 matched services for empty secret set, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// workloadConsumesAffectedService
// ---------------------------------------------------------------------------

func TestWorkloadConsumesAffectedService_Matches(t *testing.T) {
	workload := &v1alpha1.WorkloadDetails{
		Name:                "cap-backend",
		ConsumedBTPServices: []string{"cap-uaa", "cap-service-manager"},
	}
	affected := map[string]struct{}{"cap-uaa": {}}
	if !workloadConsumesAffectedService(workload, affected) {
		t.Error("expected workload to consume affected service")
	}
}

func TestWorkloadConsumesAffectedService_NoMatch(t *testing.T) {
	workload := &v1alpha1.WorkloadDetails{
		Name:                "app-router",
		ConsumedBTPServices: []string{"cap-uaa"},
	}
	affected := map[string]struct{}{"cap-service-manager": {}}
	if workloadConsumesAffectedService(workload, affected) {
		t.Error("expected workload NOT to consume affected service")
	}
}

func TestWorkloadConsumesAffectedService_EmptyConsumed(t *testing.T) {
	workload := &v1alpha1.WorkloadDetails{
		Name:                "app-router",
		ConsumedBTPServices: []string{},
	}
	affected := map[string]struct{}{"cap-uaa": {}}
	if workloadConsumesAffectedService(workload, affected) {
		t.Error("expected false when workload consumes no services")
	}
}

// ---------------------------------------------------------------------------
// rolloutManager.Enqueue + drainSecrets + restoreSecrets
// ---------------------------------------------------------------------------

func TestEnqueueAndDrainSecrets_SingleEnqueue(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.Enqueue("default", "my-secret")

	drained := m.drainSecrets("default")
	if len(drained) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(drained))
	}
	if _, ok := drained["my-secret"]; !ok {
		t.Error("expected my-secret to be present")
	}

	// second drain must be empty
	drained2 := m.drainSecrets("default")
	if len(drained2) != 0 {
		t.Error("expected empty set after second drain")
	}
}

func TestEnqueueAndDrainSecrets_MultipleSecretsCollapsed(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.Enqueue("default", "secret-a")
	m.Enqueue("default", "secret-b")
	m.Enqueue("default", "secret-a") // duplicate, should not double-count

	drained := m.drainSecrets("default")
	if len(drained) != 2 {
		t.Fatalf("expected 2 unique secrets, got %d", len(drained))
	}
}

func TestEnqueueAndDrainSecrets_MultipleNamespaces(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.Enqueue("ns-a", "secret-x")
	m.Enqueue("ns-b", "secret-y")

	drainedA := m.drainSecrets("ns-a")
	drainedB := m.drainSecrets("ns-b")

	if len(drainedA) != 1 {
		t.Errorf("expected 1 secret for ns-a, got %d", len(drainedA))
	}
	if len(drainedB) != 1 {
		t.Errorf("expected 1 secret for ns-b, got %d", len(drainedB))
	}
}

func TestDrainSecrets_UnknownNamespace(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	drained := m.drainSecrets("no-such-namespace")
	if drained != nil {
		t.Errorf("expected nil for unknown namespace, got %v", drained)
	}
}

func TestRestoreSecrets_MergesIntoExisting(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.Enqueue("default", "secret-a")
	// drain to simulate a failed processing attempt
	drained := m.drainSecrets("default")

	// a new secret arrived while processing was in-flight
	m.Enqueue("default", "secret-b")

	// restore the drained set — should merge, not overwrite
	m.restoreSecrets("default", drained)

	result := m.drainSecrets("default")
	if len(result) != 2 {
		t.Fatalf("expected 2 secrets after restore+merge, got %d", len(result))
	}
	if _, ok := result["secret-a"]; !ok {
		t.Error("expected secret-a to be present after restore")
	}
	if _, ok := result["secret-b"]; !ok {
		t.Error("expected secret-b to be present after merge")
	}
}

func TestRestoreSecrets_IntoEmptyNamespace(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.restoreSecrets("default", map[string]struct{}{"secret-x": {}})

	result := m.drainSecrets("default")
	if len(result) != 1 {
		t.Fatalf("expected 1 secret after restore into empty namespace, got %d", len(result))
	}
	if _, ok := result["secret-x"]; !ok {
		t.Error("expected secret-x to be present")
	}
}

func TestRestoreSecrets_DeduplicatesOnMerge(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	m.Enqueue("default", "secret-a")
	drained := m.drainSecrets("default")

	// same secret already re-enqueued by a concurrent Enqueue call
	m.Enqueue("default", "secret-a")
	m.restoreSecrets("default", drained)

	result := m.drainSecrets("default")
	if len(result) != 1 {
		t.Fatalf("expected 1 secret (no duplicates) after restore+merge, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// processNamespace
// ---------------------------------------------------------------------------

func TestProcessNamespace_EmptyAffectedSecrets(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})
	m := newRolloutManager(c)

	err := m.processNamespace(context.TODO(), "default", map[string]struct{}{})
	if err != nil {
		t.Fatalf("expected no error for empty affected secrets, got: %v", err)
	}
}

func TestProcessNamespace_RolloutDisabledOnCA(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", false /* rollout disabled */, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	m := newRolloutManager(c)

	// Even though the secret matches, rollout should not happen because RolloutOnCredentialUpdate=false
	err := m.processNamespace(context.TODO(), metav1.NamespaceDefault, map[string]struct{}{
		"cap-cap-01-uaa-bind-cf": {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that no deployment update was attempted
	actions := c.kubeClient.(*k8sfake.Clientset).Actions()
	for _, a := range actions {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			t.Error("expected no deployment update when rollout is disabled")
		}
	}
}

func TestProcessNamespace_NoMatchingServicesForSecrets(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	m := newRolloutManager(c)

	// Secret that doesn't match any service in the CA
	err := m.processNamespace(context.TODO(), metav1.NamespaceDefault, map[string]struct{}{
		"unrelated-secret": {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions := c.kubeClient.(*k8sfake.Clientset).Actions()
	for _, a := range actions {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			t.Error("expected no deployment update when secret doesn't match any service")
		}
	}
}

// ---------------------------------------------------------------------------
// processAffectedApplication
// ---------------------------------------------------------------------------

func TestProcessAffectedApplication_NoRelevantCAVs(t *testing.T) {
	defer deregisterMetrics()
	// CA exists but has no Ready CAVs
	ca := buildCA("test-cap-01", true, btpServices())

	c := getTestController(testResources{
		cas: []*v1alpha1.CAPApplication{ca},
	})
	m := newRolloutManager(c)

	err := m.processAffectedApplication(context.TODO(), ca, map[string]struct{}{"cap-uaa": {}})
	if err != nil {
		t.Fatalf("expected no error when no relevant CAVs, got: %v", err)
	}
}

func TestProcessAffectedApplication_WithLatestReadyCAV(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})
	deploy := buildDeployment(cav.Name, "cap-backend", metav1.NamespaceDefault)

	// credential secret needed to generate VCAP
	credSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cap-cap-01-uaa-bind-cf", Namespace: metav1.NamespaceDefault},
		Data:       map[string][]byte{"credentials": []byte(`{"url":"https://auth.local"}`)},
	}

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	// add objects to fake clients directly
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(deploy)
	c.kubeInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(deploy)
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(credSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(credSecret)

	m := newRolloutManager(c)

	err := m.processAffectedApplication(context.TODO(), ca, map[string]struct{}{"cap-uaa": {}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A new VCAP secret should have been created and the deployment updated
	createdSecret := false
	updatedDeploy := false
	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "secrets" {
			createdSecret = true
		}
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			updatedDeploy = true
		}
	}
	if !createdSecret {
		t.Error("expected a new VCAP secret to be created")
	}
	if !updatedDeploy {
		t.Error("expected the deployment to be updated with the new VCAP secret reference")
	}
}

// ---------------------------------------------------------------------------
// processAffectedVersion
// ---------------------------------------------------------------------------

func TestProcessAffectedVersion_WorkloadWithNoDeploymentDef(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			// job workload — no DeploymentDefinition
			Name:                "content-job",
			ConsumedBTPServices: []string{"cap-uaa"},
		},
	})

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	m := newRolloutManager(c)
	err := m.processAffectedVersion(context.TODO(), ca, cav, map[string]struct{}{"cap-uaa": {}})
	if err != nil {
		t.Fatalf("unexpected error for job workload: %v", err)
	}

	// No deployments should be updated for job workloads
	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			t.Error("did not expect deployment update for job workload")
		}
	}
}

func TestProcessAffectedVersion_DeploymentNotYetCreated(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	m := newRolloutManager(c)
	// No deployment pre-created → should silently skip (not an error)
	err := m.processAffectedVersion(context.TODO(), ca, cav, map[string]struct{}{"cap-uaa": {}})
	if err != nil {
		t.Fatalf("expected no error when deployment doesn't exist yet, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// replaceVCAPSecret
// ---------------------------------------------------------------------------

func TestReplaceVCAPSecret_NoExistingSecret(t *testing.T) {
	defer deregisterMetrics()
	c := getTestController(testResources{})

	ownerRef := metav1.OwnerReference{Name: "test-cap-01-cav-v1"}
	// When no secret exists, should complete without error and return unchanged=false
	unchanged, err := c.checkVCAPSecret(context.TODO(), metav1.NamespaceDefault, "test-cap-01-cav-v1-cap-backend", ownerRef, []byte(`{"xsuaa":[]}`))
	if err != nil {
		t.Fatalf("unexpected error when no VCAP secret exists: %v", err)
	}
	if unchanged {
		t.Error("expected unchanged=false when no VCAP secret exists")
	}
}

func TestReplaceVCAPSecret_DeletesExistingSecret(t *testing.T) {
	defer deregisterMetrics()

	cavName := "test-cap-01-cav-v1"
	deployName := "test-cap-01-cav-v1-cap-backend"
	ownerRef := metav1.OwnerReference{Name: cavName}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName + "-vcap-gen",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelSecretOwnerHash: sha1Sum(metav1.NamespaceDefault, cavName, deployName),
			},
		},
		Data: map[string][]byte{
			EnvVCAPServices: []byte(`{"old":[]}`),
		},
	}

	c := getTestController(testResources{})
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(existingSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(existingSecret)

	unchanged, err := c.checkVCAPSecret(context.TODO(), metav1.NamespaceDefault, deployName, ownerRef, []byte(`{"new":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unchanged {
		t.Error("expected unchanged=false when content differs")
	}

	deletedSecret := false
	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "delete" && a.GetResource().Resource == "secrets" {
			deletedSecret = true
		}
	}
	if !deletedSecret {
		t.Error("expected existing VCAP secret to be deleted")
	}
}

func TestReplaceVCAPSecret_UnchangedContentSkipsDelete(t *testing.T) {
	defer deregisterMetrics()

	cavName := "test-cap-01-cav-v1"
	deployName := "test-cap-01-cav-v1-cap-backend"
	ownerRef := metav1.OwnerReference{Name: cavName}
	vcapContent := []byte(`{"xsuaa":[{"credentials":{"url":"https://auth.local"}}]}`)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName + "-vcap-gen",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelSecretOwnerHash: sha1Sum(metav1.NamespaceDefault, cavName, deployName),
			},
		},
		Data: map[string][]byte{
			EnvVCAPServices: vcapContent,
		},
	}

	c := getTestController(testResources{})
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(existingSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(existingSecret)

	unchanged, err := c.checkVCAPSecret(context.TODO(), metav1.NamespaceDefault, deployName, ownerRef, vcapContent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unchanged {
		t.Error("expected unchanged=true when VCAP content is identical")
	}

	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "delete" && a.GetResource().Resource == "secrets" {
			t.Error("expected no secret deletion when content is unchanged")
		}
	}
}

// ---------------------------------------------------------------------------
// updateDeploymentVCAPRef
// ---------------------------------------------------------------------------

func TestUpdateDeploymentVCAPRef_UpdatesContainersAndInitContainers(t *testing.T) {
	defer deregisterMetrics()

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cap-01-cav-v1-cap-backend",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "server", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "old-vcap"}}}}},
					},
					InitContainers: []corev1.Container{
						{Name: "init", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "old-vcap"}}}}},
					},
				},
			},
		},
	}

	c := getTestController(testResources{})
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(deploy)

	err := c.updateDeploymentVCAPRef(context.TODO(), metav1.NamespaceDefault, deploy, "new-vcap-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := c.kubeClient.AppsV1().Deployments(metav1.NamespaceDefault).Get(context.TODO(), deploy.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("could not retrieve updated deployment: %v", err)
	}

	for _, ctr := range updated.Spec.Template.Spec.Containers {
		if len(ctr.EnvFrom) == 0 || ctr.EnvFrom[0].SecretRef.Name != "new-vcap-secret" {
			t.Errorf("container %s: expected EnvFrom to reference new-vcap-secret", ctr.Name)
		}
	}
	for _, ctr := range updated.Spec.Template.Spec.InitContainers {
		if len(ctr.EnvFrom) == 0 || ctr.EnvFrom[0].SecretRef.Name != "new-vcap-secret" {
			t.Errorf("init container %s: expected EnvFrom to reference new-vcap-secret", ctr.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// collectRelevantCAVs
// ---------------------------------------------------------------------------

func TestCollectRelevantCAVs_LatestReadyOnly(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{})

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})

	relevant, err := c.collectRelevantCAVs(ca)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(relevant) != 1 {
		t.Fatalf("expected 1 relevant CAV, got %d", len(relevant))
	}
	if _, ok := relevant[cav.Name]; !ok {
		t.Errorf("expected %s to be in relevant CAVs", cav.Name)
	}
}

func TestCollectRelevantCAVs_DeduplicatesLatestAndTenantCAV(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{})

	// Tenant also references the same CAV
	tenant := buildReadyTenant("test-cap-01-provider", ca.Name, cav.Name)

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
		cats: []*v1alpha1.CAPTenant{tenant},
	})

	relevant, err := c.collectRelevantCAVs(ca)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Even though the CAV appears as both latest and tenant CAV, it should be deduplicated
	if len(relevant) != 1 {
		t.Fatalf("expected 1 deduplicated CAV, got %d", len(relevant))
	}
}

func TestCollectRelevantCAVs_TenantReferencesAdditionalCAV(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())

	// Latest ready CAV
	latestCAV := buildReadyCAV("test-cap-01-cav-v2", ca.Name, []v1alpha1.WorkloadDetails{})
	latestCAV.Spec.Version = "2.0.0"

	// Older CAV still in use by a tenant
	oldCAV := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{})
	oldCAV.Spec.Version = "1.0.0"

	tenant := buildReadyTenant("test-cap-01-provider", ca.Name, oldCAV.Name)

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{latestCAV, oldCAV},
		cats: []*v1alpha1.CAPTenant{tenant},
	})

	relevant, err := c.collectRelevantCAVs(ca)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(relevant) != 2 {
		t.Fatalf("expected 2 relevant CAVs (latest + tenant), got %d", len(relevant))
	}
	if _, ok := relevant[latestCAV.Name]; !ok {
		t.Errorf("expected latestCAV %s to be relevant", latestCAV.Name)
	}
	if _, ok := relevant[oldCAV.Name]; !ok {
		t.Errorf("expected oldCAV %s to be relevant (used by tenant)", oldCAV.Name)
	}
}

// ---------------------------------------------------------------------------
// enqueuePendingRollouts
// ---------------------------------------------------------------------------

func TestEnqueuePendingRollouts_NoRelevantCAs(t *testing.T) {
	defer deregisterMetrics()
	// CA with rollout disabled — nothing should be enqueued
	ca := buildCA("test-cap-01", false, btpServices())
	c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	if err := m.enqueuePendingRollouts(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.queue.Len() != 0 {
		t.Errorf("expected empty queue for CA with rollout disabled, got %d items", m.queue.Len())
	}
}

func TestEnqueuePendingRollouts_EnqueuesNamespaceForRelevantCA(t *testing.T) {
	defer deregisterMetrics()
	ca := buildCA("test-cap-01", true, btpServices())
	c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	if err := m.enqueuePendingRollouts(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 BTP service secrets should have been recorded for the namespace
	drained := m.drainSecrets(metav1.NamespaceDefault)
	if len(drained) != len(btpServices()) {
		t.Errorf("expected %d secrets enqueued, got %d", len(btpServices()), len(drained))
	}
	for _, svc := range btpServices() {
		if _, ok := drained[svc.Secret]; !ok {
			t.Errorf("expected secret %s to be enqueued", svc.Secret)
		}
	}
}

func TestEnqueuePendingRollouts_MultipleCAsSameNamespaceDeduplicatesSecrets(t *testing.T) {
	defer deregisterMetrics()
	// Two CAs in the same namespace sharing one secret — should only enqueue it once
	sharedSecret := "shared-secret"
	ca1 := buildCA("test-cap-01", true, []v1alpha1.ServiceInfo{
		{Class: "xsuaa", Name: "svc-a", Secret: sharedSecret},
	})
	ca2 := buildCA("test-cap-02", true, []v1alpha1.ServiceInfo{
		{Class: "xsuaa", Name: "svc-b", Secret: sharedSecret},
		{Class: "saas-registry", Name: "svc-c", Secret: "unique-secret"},
	})
	c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca1, ca2}})
	m := newRolloutManager(c)
	defer m.queue.ShutDown()

	if err := m.enqueuePendingRollouts(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	drained := m.drainSecrets(metav1.NamespaceDefault)
	if len(drained) != 2 {
		t.Errorf("expected 2 unique secrets (shared deduped), got %d", len(drained))
	}
}

// ---------------------------------------------------------------------------
// Full rollout path through processNamespace
// ---------------------------------------------------------------------------

func TestProcessNamespace_FullRollout(t *testing.T) {
	defer deregisterMetrics()

	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
		{
			// App-router does NOT consume cap-uaa, should not be rolled out
			Name:                "app-router",
			ConsumedBTPServices: []string{"cap-saas-registry"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})

	backendDeploy := buildDeployment(cav.Name, "cap-backend", metav1.NamespaceDefault)
	routerDeploy := buildDeployment(cav.Name, "app-router", metav1.NamespaceDefault)

	credSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cap-cap-01-uaa-bind-cf", Namespace: metav1.NamespaceDefault},
		Data:       map[string][]byte{"credentials": []byte(`{"url":"https://auth.local"}`)},
	}

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	for _, obj := range []interface{ GetName() string }{backendDeploy, routerDeploy} {
		switch o := obj.(type) {
		case *appsv1.Deployment:
			c.kubeClient.(*k8sfake.Clientset).Tracker().Add(o)
			c.kubeInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(o)
		}
	}
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(credSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(credSecret)

	m := newRolloutManager(c)

	err := m.processNamespace(context.TODO(), metav1.NamespaceDefault, map[string]struct{}{
		"cap-cap-01-uaa-bind-cf": {},
	})
	if err != nil {
		t.Fatalf("unexpected error during full rollout: %v", err)
	}

	updatedDeployments := map[string]bool{}
	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			ua := a.(k8stesting.UpdateAction)
			dep := ua.GetObject().(*appsv1.Deployment)
			updatedDeployments[dep.Name] = true
		}
	}

	if !updatedDeployments[backendDeploy.Name] {
		t.Errorf("expected cap-backend deployment to be rolled out")
	}
	if updatedDeployments[routerDeploy.Name] {
		t.Errorf("expected app-router NOT to be rolled out (doesn't consume affected service)")
	}
}

func TestProcessNamespace_SkipsRolloutWhenVCAPUnchanged(t *testing.T) {
	defer deregisterMetrics()

	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})

	backendDeploy := buildDeployment(cav.Name, "cap-backend", metav1.NamespaceDefault)

	credSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cap-cap-01-uaa-bind-cf", Namespace: metav1.NamespaceDefault},
		Data:       map[string][]byte{"credentials": []byte(`{"url":"https://auth.local"}`)},
	}

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(backendDeploy)
	c.kubeInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(backendDeploy)
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(credSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(credSecret)

	// Pre-compute the VCAP content that rolloutWorkloadDeployment would generate,
	// then seed a secret with that exact content so checkVCAPSecret returns unchanged=true.
	deploymentName := getWorkloadName(cav.Name, "cap-backend")
	ownerRef := *metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind))
	consumedServiceInfos := getConsumedServiceInfos(getConsumedServiceMap([]string{"cap-uaa"}), ca.Spec.BTP.Services)
	vcapEnv, err := generateVCAPEnv(metav1.NamespaceDefault, consumedServiceInfos, c.kubeInformerFactory)
	if err != nil {
		t.Fatalf("failed to pre-generate VCAP env: %v", err)
	}
	existingVCAPSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName + "-vcap-existing",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelSecretOwnerHash: sha1Sum(metav1.NamespaceDefault, ownerRef.Name, deploymentName),
			},
		},
		Data: map[string][]byte{
			EnvVCAPServices: vcapEnv,
		},
	}
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(existingVCAPSecret)
	c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(existingVCAPSecret)

	m := newRolloutManager(c)

	err = m.processNamespace(context.TODO(), metav1.NamespaceDefault, map[string]struct{}{
		"cap-cap-01-uaa-bind-cf": {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, a := range c.kubeClient.(*k8sfake.Clientset).Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			t.Error("expected no deployment update when VCAP_SERVICES content is unchanged")
		}
		if a.GetVerb() == "create" && a.GetResource().Resource == "secrets" {
			t.Error("expected no new VCAP secret to be created when content is unchanged")
		}
	}
}

// ---------------------------------------------------------------------------
// Queue-based worker loop
// ---------------------------------------------------------------------------

// waitFor polls pred every 10 ms until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, pred func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// newFastRolloutManager returns a rolloutManager with rolloutDelay=0 so
// AddAfter fires immediately in tests.
func newFastRolloutManager(c *Controller) *rolloutManager {
	m := newRolloutManager(c)
	m.rolloutDelay = 0
	return m
}

// TestStartWorker_SuccessPath verifies that after a successful processNamespace
// the item is Forgotten (requeue count resets to 0) and Done is called so the
// queue length returns to 0.
func TestStartWorker_SuccessPath(t *testing.T) {
	defer deregisterMetrics()

	ca := buildCA("test-cap-01", true, btpServices())
	c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}})
	m := newFastRolloutManager(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Start(ctx)

	// Enqueue a namespace with a secret that matches no service → processNamespace
	// succeeds (returns nil) without touching Kubernetes.
	m.Enqueue(metav1.NamespaceDefault, "unrelated-secret")

	// The worker should drain the item and forget it; queue must reach length 0.
	if !waitFor(t, 2*time.Second, func() bool { return m.queue.Len() == 0 }) {
		t.Fatal("queue did not drain after successful processing")
	}

	// Requeue counter must be 0 — Forget was called on the success path.
	if got := m.queue.NumRequeues(metav1.NamespaceDefault); got != 0 {
		t.Errorf("expected 0 requeues after success, got %d", got)
	}
}

// TestStartWorker_ErrorPathRestoresSecretsAndRequeues verifies the error branch
// of the queue worker (lines 133-135): when processNamespace returns an error
// (here: the credential secret referenced by a workload's ConsumedBTPServices is
// absent, causing generateVCAPEnv to fail inside rolloutWorkloadDeployment),
// the worker must restore the drained secrets and rate-limit the item for retry.
func TestStartWorker_ErrorPathRestoresSecretsAndRequeues(t *testing.T) {
	defer deregisterMetrics()

	ca := buildCA("test-cap-01", true, btpServices())
	cav := buildReadyCAV("test-cap-01-cav-v1", ca.Name, []v1alpha1.WorkloadDetails{
		{
			Name:                "cap-backend",
			ConsumedBTPServices: []string{"cap-uaa"},
			DeploymentDefinition: &v1alpha1.DeploymentDetails{
				CommonDetails: v1alpha1.CommonDetails{Image: "test://image"},
			},
		},
	})
	// Deployment exists so rolloutWorkloadDeployment proceeds past the IsNotFound skip ...
	deploy := buildDeployment(cav.Name, "cap-backend", metav1.NamespaceDefault)

	c := getTestController(testResources{
		cas:  []*v1alpha1.CAPApplication{ca},
		cavs: []*v1alpha1.CAPApplicationVersion{cav},
	})
	c.kubeClient.(*k8sfake.Clientset).Tracker().Add(deploy)
	c.kubeInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(deploy)
	// ... but the credential secret is intentionally absent so generateVCAPEnv errors.

	m := newFastRolloutManager(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Start(ctx)

	m.Enqueue(metav1.NamespaceDefault, "cap-cap-01-uaa-bind-cf")

	// Wait until the worker has hit the error path and rate-limited the item.
	if !waitFor(t, 2*time.Second, func() bool {
		return m.queue.NumRequeues(metav1.NamespaceDefault) >= 1
	}) {
		t.Fatal("item was not rate-limited after processing error")
	}

	// Secret must have been restored into pendingSecrets for the retry.
	m.mu.Lock()
	_, restored := m.pendingSecrets[metav1.NamespaceDefault]["cap-cap-01-uaa-bind-cf"]
	m.mu.Unlock()
	if !restored {
		t.Error("expected cap-cap-01-uaa-bind-cf to be restored into pendingSecrets after error")
	}
}

// TestStartWorker_ShutdownDrainsWorkers verifies that cancelling the context
// causes Start to return (workers notice shutdown and exit).
func TestStartWorker_ShutdownDrainsWorkers(t *testing.T) {
	defer deregisterMetrics()

	c := getTestController(testResources{})
	m := newFastRolloutManager(c)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Start returned as expected
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// TestStartWorker_DrainSecretsCalledBeforeProcessing verifies that the worker
// atomically drains pendingSecrets before calling processNamespace, so secrets
// enqueued after the drain but before completion are not lost.
func TestStartWorker_DrainSecretsCalledBeforeProcessing(t *testing.T) {
	defer deregisterMetrics()

	ca := buildCA("test-cap-01", true, btpServices())
	c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}})
	m := newFastRolloutManager(c)

	// Pre-populate two secrets for the same namespace.
	m.Enqueue(metav1.NamespaceDefault, "secret-a")
	m.Enqueue(metav1.NamespaceDefault, "secret-b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Start(ctx)

	// Both secrets should be consumed in the single processing pass (batching).
	// pendingSecrets for the namespace should be empty once the queue is drained.
	if !waitFor(t, 2*time.Second, func() bool {
		return m.queue.Len() == 0
	}) {
		t.Fatal("queue did not drain after processing both secrets")
	}

	m.mu.Lock()
	remaining := len(m.pendingSecrets[metav1.NamespaceDefault])
	m.mu.Unlock()

	if remaining != 0 {
		t.Errorf("expected pendingSecrets to be empty after drain, got %d entries", remaining)
	}
}
