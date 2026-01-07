/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

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
			description: "With label and finalizer, processing initial state",
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

func TestDomain_ProcessingWithIngressWithAdditionalCACertificate(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress - ObservedDomain getting set, cert, secret and gateway getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-additionalCACertificate.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-observedDom-cert-secret-gateway.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_ProcessingWithIngressWithAdditionalCACertificateCreateFailed(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress - ObservedDomain getting set, cert created, secret creation failed",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-additionalCACertificate.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "create", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)

	if err.Error() != "failed to reconcile additional ca certificate secret for Domain.default.test-cap-01-primary: failed to create additional ca certificate secret for Domain.default.test-cap-01-primary: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_ProcessingWithIngressCertManager(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress - ObservedDomain getting set, certManager and gateway getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-observedDom-certManager-gateway.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestDomain_ProcessingWithIngressCertManagerWithAdditionalCACertificate(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress - ObservedDomain getting set, certManager, secret and gateway getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-additionalCACertificate.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-observedDom-certManager-secret-gateway.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)

	os.Setenv(certManagerEnv, "")
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

func TestDomain_Mutual(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, cert, dns and updated gateway with mutual TLS ready - Domain ready",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-mutual.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-mutual-ready.yaml",
		},
	)
}

func TestDomain_OptionalMutual(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Processing with ingress, ObservedDomain set, cert, dns and missing gateway with Optional Mutual TLS ready - Domain ready",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-optional-mutual.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-optional-mutual-ready.yaml",
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
				"testdata/domain/primary-gateway-cert-manager.yaml",
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

func TestDomain_UpdateAdditionalCACertificate(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain updated - Additional CA Certificate getting updated",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-additionalCaCertificate-update.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectedResources: "testdata/domain/domain-additionalCaCertificate-update.expected.yaml",
		},
	)
}

func TestDomain_UpdateAdditionalCACertificateNoHashChange(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain updated - Additional CA Certificate not getting updated as hash did not change",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-additionalCACertificate.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectedResources: "testdata/domain/domain-ready-additiionCACertificate.yaml",
		},
	)
}

func TestDomain_UpdateAdditionalCACertificateGetError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain update - Additional CA Certificate update failed; exisiting secret get returned error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-additionalCaCertificate-update.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "get", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)

	if err.Error() != "failed to reconcile additional ca certificate secret for Domain.default.test-cap-01-primary: failed to get existing secret: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_UpdateAdditionalCACertificateUpdateError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain update - Additional CA Certificate update failed as exisiting secret update returned error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-additionalCaCertificate-update.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "update", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)

	if err.Error() != "failed to reconcile additional ca certificate secret for Domain.default.test-cap-01-primary: failed to update additional ca certificate secret for Domain.default.test-cap-01-primary: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_RemoveAdditionalCACertificate(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain updated - Additional CA Certificate secret getting deleted",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-without-additionalCaCertificate.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_RemoveAdditionalCACertificateDeleteError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain update - Additional CA Certificate secret delete error",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
				"testdata/domain/primary-dns-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "delete", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)

	if err.Error() != "failed to reconcile additional ca certificate secret for Domain.default.test-cap-01-primary: failed to delete stale ca certificate secret default--test-cap-01-primary-gardener-cacert for Domain.default.test-cap-01-primary: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_UpdatedomainWithCertManager(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain updated using certManager - gateway and dns getting updated",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-update.yaml",
				"testdata/domain/primary-certManager-ready.yaml",
				"testdata/domain/primary-gateway-cert-manager.yaml",
				"testdata/domain/primary-dns-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-update.expected-certManager.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)

	os.Setenv(certManagerEnv, "")
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
			description: "Domain deleting with certificates and additionalCaCertificateSecret - Finalizer removed",
			initialResources: []string{
				"testdata/domain/domain-deleting.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectedResources: "testdata/domain/domain-deleting-no-finalizer.yaml",
		},
	)
}

func TestDomain_DeletingWithCertSecretListError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain deleting with certificates and additionalCaCertificateSecret - Secret list error",
			initialResources: []string{
				"testdata/domain/domain-deleting.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "list", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)
	if err.Error() != "failed to delete additional ca certificate secret for Domain.default.test-cap-01-primary: failed to list additional ca certificate secrets for Domain.default.test-cap-01-primary: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_DeletingWithCertSecretDeleteError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain deleting with certificates and additionalCaCertificateSecret - Secret delete error",
			initialResources: []string{
				"testdata/domain/domain-deleting.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "delete", Group: "", Version: "v1", Resource: "secrets", Namespace: "*", Name: "*"}},
		},
	)
	if err.Error() != "failed to delete additional ca certificate secret for Domain.default.test-cap-01-primary: failed to delete additional ca certificate secret istio-system.default--test-cap-01-primary-gardener-cacert for Domain.default.test-cap-01-primary: mocked api error (secrets./v1)" {
		t.Error("Wrong error message")
	}
}

func TestDomain_DeletingWithCertManager(t *testing.T) {
	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain deleting with certificates and additionalCaCertificateSecret - Finalizer removed",
			initialResources: []string{
				"testdata/domain/domain-deleting.yaml",
				"testdata/domain/primary-certManager-ready.yaml",
				"testdata/domain/additional-caCertificate-secret.yaml",
			},
			expectedResources: "testdata/domain/domain-deleting-no-finalizer.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestDomain_DuplicateDomains(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary-dup"}},
		TestData{
			description: "Duplicate domains",
			initialResources: []string{
				"testdata/domain/domain-ready.yaml",
				"testdata/domain/domain-duplicate.yaml",
			},
			expectedResources: "testdata/domain/domain-duplicate.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}, {Namespace: "default", Name: "test-cap-01-primary-dup"}}},
		},
	)
}

func TestDomain_SubdomainWithCAService(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain with type subdomain and CA service only - dns and netpol getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-with-subdomain-processing.yaml",
				"testdata/domain/ca-services-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-with-subdomain-processing-with-dns-netpol.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_SubdomainWithCATenanat(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain with type subdomain and CA with provider tenant - dns and netpol getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-with-subdomain-processing.yaml",
				"testdata/capapplication/ca-06.expected.yaml",
				"testdata/common/captenant-provider-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-with-subdomain-processing-with-dns-netpol-cat.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_CADeleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain with type subdomain and CA deleted - dns and netpol getting deleted",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-with-subdomain-processing-with-dns-netpol.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-with-subdomain-ready.yaml",
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

func TestDomain_UpdateOldDNS(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain reconciled - dns labels getting updated",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-processing-old-dns.yaml",
				"testdata/domain/primary-certificate-ready.yaml",
				"testdata/domain/primary-gateway.yaml",
			},
			expectedResources: "testdata/domain/domain-processing-updated-dns.yaml",
		},
	)
}

func TestDomain_CustomDNSServices(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain with CustomDNS templates and CA service only - dns and netpol getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-with-customDNS-processing.yaml",
				"testdata/domain/ca-services-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-with-customDNS-services.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}

func TestDomain_CustomDNSTenants(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceDomain, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-primary"}},
		TestData{
			description: "Domain with CustomDNS templates and CA with provider tenant - dns and netpol getting created",
			initialResources: []string{
				"testdata/domain/istio-ingress.yaml",
				"testdata/domain/domain-with-customDNS-processing.yaml",
				"testdata/capapplication/ca-06.expected.yaml",
				"testdata/common/captenant-provider-ready.yaml",
			},
			expectedResources: "testdata/domain/domain-with-customDNS-tenant.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceDomain: {{Namespace: "default", Name: "test-cap-01-primary"}}},
		},
	)
}
