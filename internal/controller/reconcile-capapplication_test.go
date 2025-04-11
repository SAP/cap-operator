/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"os"
	"testing"
)

func TestCAPApplicationWithoutPreExistingLabelAndNilInitialState(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Initial test without pre-existing label and nil initial state",
			initialResources: []string{
				"testdata/capapplication/ca-01.initial.yaml",
			},
			expectedResources: "testdata/capapplication/ca-01.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestCAPApplicationWithLabelsAndFinalizersEmptyState(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "application labels and finalizers set, empty state - expect processing state",
			initialResources: []string{
				"testdata/capapplication/ca-42.initial.yaml",
			},
			expectedResources: "testdata/capapplication/ca-42.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestCAPApplicationWithPreExistingLabelAndProcessingInitialState(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Initial test with pre-existing label, processing initial state and invalid secret",
			initialResources: []string{
				"testdata/capapplication/ca-02.initial.yaml",
			},
			expectedResources: "testdata/capapplication/ca-02.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestCAPApplicationWithValidSecret(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Test with pre-existing label, processing state and valid secret",
			initialResources: []string{
				"testdata/capapplication/ca-03.initial.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-03.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestValidationOfBtpServicesWithoutSecrets(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Invalid BTPServices with high attempts",
			initialResources: []string{
				"testdata/capapplication/ca-02.initial.yaml",
			},
			expectedResources: "testdata/capapplication/ca-02.expected.yaml",
			attempts:          9999,
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestValidationOfBtpServicesWithSecrets(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Valid BTPServices with high attempts",
			initialResources: []string{
				"testdata/capapplication/ca-03.initial.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-03.expected.yaml",
			attempts:          9999,
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestCavCatGateway_Case1(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - provisioning, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-04.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-04.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestCavCatGateway_Case2(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - error, CAPTenant - provisioning, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-05.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/capapplication/cav-error.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-05.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestCavCatGateway_Case3(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-06.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-06.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestCavCatGateway_Case4(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - NA, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-07.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/common/istio-ingress.yaml",
			},
			expectedResources: "testdata/capapplication/ca-07.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				// ResourceOperatorDomains: {{Namespace: "", Name: ""}},
				ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}},
				ResourceCAPTenant:      {{Namespace: "default", Name: "test-cap-01-provider"}},
			},
		},
	)
}

func TestCavCatGateway_Case5(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-08.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/common/istio-ingress.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-08.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				// ResourceOperatorDomains: {{Namespace: "", Name: ""}},
				ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}},
				ResourceCAPTenant:      {{Namespace: "default", Name: "test-cap-01-provider"}},
			},
		},
	)
}

func TestCavCatGateway_Case6(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - error, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-09.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-error.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-09.expected.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "provider CAPTenant in state ProvisioningError for CAPApplication default.test-cap-01" {
		t.Error("Wrong error message")
	}
}

func TestCavCatGateway_Case7(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - error, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-10.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert-error.yaml",
			},
			expectedResources: "testdata/capapplication/ca-10.expected.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "Certificate in state Error for CAPApplication default.test-cap-01: cert message" {
		t.Error("Wrong error message")
	}
}

func TestCavCatGateway_Case8(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - error",
			initialResources: []string{
				"testdata/capapplication/ca-11.initial.yaml",
				"testdata/capapplication/ca-dns-error.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-11.expected.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "DNSEntry in state Error for CAPApplication default.test-cap-01: dns message" {
		t.Error("Wrong error message")
	}
}

func TestCavCatGateway_Case9(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - upgrade error, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-12.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-upgrade-error.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-12.expected.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "provider CAPTenant in state UpgradeError for CAPApplication default.test-cap-01" {
		t.Error("Wrong error message")
	}
}

func TestDeletion_Case1(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Without deletionTimestamp and without finalizer set",
			initialResources: []string{
				"testdata/capapplication/ca-13.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-13.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestDeletion_Case2(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletionTimestamp and without finalizer set",
			initialResources: []string{
				"testdata/capapplication/ca-14.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-14.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestDeletion_Case3(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletionTimestamp and with finalizer set",
			initialResources: []string{
				"testdata/capapplication/ca-15.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-cert-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-15.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestDeletion_Case4(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered, no finalizer on certificate & provider tenant doesn't exist",
			initialResources: []string{
				"testdata/capapplication/ca-16.initial.yaml",
				"testdata/capapplication/istio-ingress-with-cert-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-16.expected.yaml",
		},
	)
}

func TestDeletion_Case5(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered, no finalizer on certificate & provider tenant exists",
			initialResources: []string{
				"testdata/capapplication/ca-17.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-cert-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-17.expected.yaml",
		},
	)
}

func TestDeletion_Case6(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered, no certificate & provider tenant exists",
			initialResources: []string{
				"testdata/capapplication/ca-18.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/istio-ingress.yaml",
			},
			expectedResources: "testdata/capapplication/ca-18.expected.yaml",
		},
	)
}

func TestDeletion_Case7(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered, finalizer on certificate & provider tenant doesn't exist",
			initialResources: []string{
				"testdata/capapplication/ca-19.initial.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-19.expected.yaml",
		},
	)
}

func TestDeletion_Case8(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered, finalizer on certificate & provider tenant exists",
			initialResources: []string{
				"testdata/capapplication/ca-20.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-20.expected.yaml",
		},
	)
}

func TestCertManagerCavCatGateway_Case1(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - provisioning, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-21.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-21.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestCertManagerCavCatGateway_Case2(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - error, CAPTenant - provisioning, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-22.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/capapplication/cav-error.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-22.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestCertManagerCavCatGateway_Case3(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-23.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-23.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestCertManagerCavCatGateway_Case4(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - NA, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-24.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/istio-ingress.yaml",
			},
			expectedResources: "testdata/capapplication/ca-24.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				// ResourceOperatorDomains: {{Namespace: "", Name: ""}},
				ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}},
				ResourceCAPTenant:      {{Namespace: "default", Name: "test-cap-01-provider"}},
			},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestCertManagerCavCatGateway_Case5(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-25.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-25.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				// ResourceOperatorDomains: {{Namespace: "", Name: ""}},
				ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}},
				ResourceCAPTenant:      {{Namespace: "default", Name: "test-cap-01-provider"}},
			},
		},
	)

	os.Setenv(certManagerEnv, "")
}

func TestCertManagerCavCatGateway_Case6(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - error, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-26.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-error.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-26.expected.yaml",
			expectError:       true,
		},
	)

	os.Setenv(certManagerEnv, "")

	if err.Error() != "provider CAPTenant in state ProvisioningError for CAPApplication default.test-cap-01" {
		t.Error("Wrong error message")
	}
}

func TestCertManagerCavCatGateway_Case7(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - error, dnsEntry - NA",
			initialResources: []string{
				"testdata/capapplication/ca-27.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager-error.yaml",
			},
			expectedResources: "testdata/capapplication/ca-27.expected.yaml",
			expectError:       true,
		},
	)

	os.Setenv(certManagerEnv, "")

	if err.Error() != "Certificate in state not ready for CAPApplication default.test-cap-01: cert message" {
		t.Error("Wrong error message")
	}
}

func TestCertManagerCavCatGateway_Case8(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - error",
			initialResources: []string{
				"testdata/capapplication/ca-28.initial.yaml",
				"testdata/capapplication/ca-dns-error.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-28.expected.yaml",
			expectError:       true,
		},
	)

	os.Setenv(certManagerEnv, "")

	if err.Error() != "DNSEntry in state Error for CAPApplication default.test-cap-01: dns message" {
		t.Error("Wrong error message")
	}
}

func TestCertManagerDeletion_Case1(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - false, finalizer set - false, certificate - ready, certificate finalizer - true, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-34.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-34.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3351",
			},
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case2(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - false, certificate - ready, certificate finalizer - true, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-35.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-35.expected.yaml",
			expectedRequeue:   nil, //When no finalizer is set --> do not expect requeue
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case3(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - ready, certificate finalizer - false, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-36.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-certManager-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-36.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case4(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - ready, certificate finalizer - false, Provider & Consumer tenant with no finalizers - NA",
			initialResources: []string{
				"testdata/capapplication/ca-37.initial.yaml",
				"testdata/capapplication/istio-ingress-with-certManager-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-37.expected.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case5(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - ready, certificate finalizer - false, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-38.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-certManager-no-finalizers.yaml",
			},
			expectedResources: "testdata/capapplication/ca-38.expected.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case6(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - NA, certificate finalizer - false, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-39.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/istio-ingress.yaml",
			},
			expectedResources: "testdata/capapplication/ca-39.expected.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case7(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - ready, certificate finalizer - true, Provider & Consumer tenant with no finalizers - NA",
			initialResources: []string{
				"testdata/capapplication/ca-40.initial.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-40.expected.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestCertManagerDeletion_Case8(t *testing.T) {

	os.Setenv(certManagerEnv, certManagerCertManagerIO)

	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When deletionTimestamp - true, finalizer set - true, certificate - ready, certificate finalizer - true, Provider & Consumer tenant with no finalizers - ready",
			initialResources: []string{
				"testdata/capapplication/ca-41.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/capapplication/istio-ingress-with-certManager.yaml",
			},
			expectedResources: "testdata/capapplication/ca-41.expected.yaml",
		},
	)

	os.Setenv(certManagerEnv, "")

}

func TestController_handleCAPApplicationConsistent_Case1(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state",
			initialResources: []string{
				"testdata/capapplication/ca-29.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-29.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case2(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with Generation mismatch",
			initialResources: []string{
				"testdata/capapplication/ca-30.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
			},
			expectedResources: "testdata/capapplication/ca-30.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case3(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a CAV name update; one tenant with fixed version and never upgrade",
			initialResources: []string{
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-31.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case4(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a CAV name update",
			initialResources: []string{
				"testdata/capapplication/ca-32.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-32.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case5(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a CAV name update",
			initialResources: []string{
				"testdata/capapplication/ca-33.initial.yaml",
				"testdata/capapplication/cav-33-version-updated-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-33.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case6(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with no certificate",
			initialResources: []string{
				"testdata/capapplication/ca-29.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-no-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-29.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2976",
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestProviderTenantCreationError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - n/a, gateway - available, certificate - ready, dnsEntry - ready",
			initialResources: []string{
				"testdata/capapplication/ca-43.initial.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources:     "testdata/capapplication/ca-43.expected.yaml",
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "create", Group: "sme.sap.com", Version: "v1alpha1", Resource: "captenants", Namespace: "*", Name: "*"}},
		},
	)

	if err.Error() != "mocked api error (captenants.sme.sap.com/v1alpha1)" {
		t.Error("Wrong error message")
	}
}

func TestCAPApplicationPrimaryDomainDNSEntryNotReady(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, gateway - available, certificate - ready, dnsEntry - not ready",
			initialResources: []string{
				"testdata/capapplication/ca-06.initial.yaml",
				"testdata/capapplication/ca-dns-not-ready.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
			},
			expectedResources: "testdata/capapplication/ca-44.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-cap-01"}}},
		},
	)
}

func TestCAPApplicationConsistentWithNewCAPApplicationVersionTenantUpdateError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a new CAV (ready); tenant update failure",
			initialResources: []string{
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "update", Group: "sme.sap.com", Version: "v1alpha1", Resource: "captenants", Namespace: "*", Name: "*"}},
		},
	)
	if err.Error() != "could not update CAPTenant default.test-cap-01-provider: mocked api error (captenants.sme.sap.com/v1alpha1)" {
		t.Error("error message is different from expected")
	}
}

func TestAdditionalConditionsTenantReadyUpgradeStrategyNever(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "test additional conditions with tenant having upgrade strategy never - and not on latest version",
			initialResources: []string{
				"testdata/capapplication/ca-45.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/captenant-provider-upgraded-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-ready.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-29.expected.yaml", // expect - AllTenantsReady is "True"
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2881"},
		},
	)
}

func TestAdditionalConditionsWithTenantDeletingUpgradeStrategyNever(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "test additional conditions with tenant having upgrade strategy never, not on latest version and deleting",
			initialResources: []string{
				"testdata/capapplication/ca-45.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/captenant-provider-upgraded-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-deleting.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-45.expected.yaml", // expect - AllTenantsReady is "False"
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2881"},
		},
	)
}

func TestController_handleCAPApplicationConsistent_versionUpgrade(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a CAV upgrade; one tenant already in upgrading state",
			initialResources: []string{
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-upgrading.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
			},
			expectedResources: "testdata/capapplication/ca-31.expected.yaml",
		},
	)
}

func TestCA_ServicesOnly_Reconcile(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - version with services only workload",
			initialResources: []string{
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-dns-entries.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       false,
			expectedResources: "testdata/capapplication/ca-services-dns.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-ca-01"}}},
		},
	)
}

func TestCA_ServicesOnlyÈrror(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - version with services only workload",
			initialResources: []string{
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-dns-entries.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       true,
			expectedResources: "testdata/capapplication/ca-services-dns.yaml",
		},
	)
}

func TestCA_ServicesOnly_Consistent(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - version with services only workload",
			initialResources: []string{
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/capapplication/gateway.yaml",
				"testdata/capapplication/istio-ingress-with-cert.yaml",
				"testdata/capapplication/ca-dns.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-dns-entries.yaml",
				"testdata/common/service-virtualservices.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       false,
			expectedResources: "testdata/capapplication/ca-services-dns-ready.yaml",
		},
	)
}
