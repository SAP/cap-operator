package controller

import (
	"context"
	"os"
	"testing"
)

func TestDomain_MissingLabelAndFinalizer(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Initial test with no label and no finalizer",
			initialResources: []string{
				"testdata/domain/domain-initial-state.yaml",
			},
			expectedResources: "testdata/domain/domain-initial-state-label-finalizer.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_InitialState(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "With label and finalizer, processing inital state",
			initialResources: []string{
				"testdata/domain/domain-initial-state-label-finalizer.yaml",
			},
			expectedResources: "testdata/domain/domain-processing.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_ProcessingWithoutIngress(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing without ingress",
			initialResources: []string{
				"testdata/domain/domain-processing.yaml",
			},
			expectedResources: "testdata/domain/domain-no-ingress-error.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "failed to get ingress information for Domain.default.test-cap-01-primary: no matching ingress gateway pods found matching selector from Domain.default.test-cap-01-primary" {
		t.Error("Wrong error message")
	}
}

// REVISIT CANNOT READ CERTIFICATE
func TestDomain_ProcessingWithIngress(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress - ObservedDomain getting set, cert and gateway getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-observedDom-cert-gateway.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_ProcessingWithIngressCertGateway(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, cert and gateway ready - dns getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-dns.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_Ready(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, cert, dns and gateway ready - Domain ready",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-ready.yaml",
		},
	)
}

func TestDomain_ReadyWithCertManager(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, certManager, dns and gateway ready - Domain ready",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certManager-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-ready.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestDomain_DnsError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, cert ready, dns error - Domain error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-error.yaml",
			},
			expectedResources: "testdata/domain/domain-dns-error.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "DNSEntry in state Error for Domain.default.test-cap-01-primary: dns message" {
		t.Error("Wrong error message")
	}
}

func TestDomain_CertificateError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, certificate error, dns ready - Domain error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certificate-error.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-cert-error.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "Certificate has state Error: certificate error" {
		t.Error("Wrong error message")
	}
}

func TestDomain_CertManagerError(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, certManager error, dns ready - Domain error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-observedDom.yaml",
				"testdata/domain/primary-certManager-error.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-certManager-error.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "Certificate not ready: Error cert-manager message error" {
		t.Error("Wrong error message")
	}

	os.Setenv(certManagerEnv, "")
}

func TestDomain_Updatedomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain updated - gateway and dns getting updated",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-update.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-update.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_DeletionTimestampSet(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain ready and deletion timestamp set - Domain deleting",
			initialResources: []string{
				"testdata/domain/domain-ready-withDeletionTimestamp.yaml",
			},
			expectedResources: "testdata/domain/domain-deleting.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_DeletingWithCert(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain deleting with certificates - Finalizer removed",
			initialResources: []string{
				"testdata/domain/domain-deleting.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-deleting-no-finalizer.yaml",
		},
	)
}

func TestClusterDomain_MissingLabelAndFinalizer(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceClusterDomain, ResourceKey: NamespacedResourceKey{Namespace: "", Name: "test-cap-01-secondary"}},
		TestData{
			description: "Initial test with no label and no finalizer",
			initialResources: []string{
				"testdata/domain/cluster-domain-initial-state.yaml",
			},
			expectedResources: "testdata/domain/cluster-domain-initial-state-label-finalizer.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceClusterDomain: {{Namespace: "", Name: "test-cap-01-secondary"}}},
		},
	)
}

func TestClusterDomain_DeletionTimestampSet(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceClusterDomain, ResourceKey: NamespacedResourceKey{Namespace: "", Name: "test-cap-01-secondary"}},
		TestData{
			description: "ClusterDomain ready and deletion timestamp set - ClusterDomain deleting",
			initialResources: []string{
				"testdata/domain/cluster-domain-ready-withDeletionTimestamp.yaml",
			},
			expectedResources: "testdata/domain/cluster-domain-deleting.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceClusterDomain: {{Namespace: "", Name: "test-cap-01-secondary"}}},
		},
	)
}

func TestClusterDomain_DeletingFinalizerRemoved(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceClusterDomain, ResourceKey: NamespacedResourceKey{Namespace: "", Name: "test-cap-01-secondary"}},
		TestData{
			description: "ClusterDomain deleting - Finalizer removed",
			initialResources: []string{
				"testdata/domain/cluster-domain-deleting.yaml",
			},
			expectedResources: "testdata/domain/cluster-domain-deleting-no-finalizer.yaml",
		},
	)
}
