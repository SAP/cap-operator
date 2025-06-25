/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-03.initial.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-03.initial.yaml",
				"testdata/common/credential-secrets.yaml",
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
			description: "When CAPApplicationVersion - ready, CAPTenant - provisioning, domain - ready, clusterdomain - ready",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-04.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
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
			description: "When CAPApplicationVersion - error, CAPTenant - provisioning, domain - ready, clusterdomain - ready",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-05.initial.yaml",
				"testdata/capapplication/cav-error.yaml",
				"testdata/common/credential-secrets.yaml",
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
			description: "When CAPApplicationVersion - ready, CAPTenant - ready, domain - ready, clusterdomain - ready",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-06.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-06.expected.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2881",
			},
		},
	)
}

func TestCavCatGateway_Case6(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - error, domain - ready, clusterdomain - ready",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-09.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-error.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-09.expected.yaml",
			expectError:       true,
		},
	)

	if err.Error() != "provider CAPTenant in state ProvisioningError for CAPApplication default.test-cap-01" {
		t.Error("Wrong error message")
	}
}

func TestCavCatGateway_Case9(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "When CAPApplicationVersion - ready, CAPTenant - upgrade error, domain - ready, clusterdomain - ready",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-12.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-upgrade-error.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-13.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-14.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-15.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
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
			description: "With deletion triggered & provider tenant doesn't exist",
			initialResources: []string{
				"testdata/capapplication/ca-16.initial.yaml",
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
			description: "With deletion triggered & provider tenant exists",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-17.initial.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
			},
			expectedResources: "testdata/capapplication/ca-17.expected.yaml",
		},
	)
}

func TestDeletion_Case7(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "With deletion triggered & provider tenant doesn't exist",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-19.initial.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-19.expected.yaml",
		},
	)
}

func TestController_handleCAPApplicationConsistent_Case1(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-29.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-ready.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-32.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-33.initial.yaml",
				"testdata/capapplication/cav-33-version-updated-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-33.expected.yaml",
			backlogItems: []string{
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
			description: "When CAPApplicationVersion - ready, CAPTenant - n/a",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-43.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
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

func TestCAPApplicationConsistentWithNewCAPApplicationVersionTenantUpdateError(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01"}},
		TestData{
			description: "Consistent state with a new CAV (ready); tenant update failure",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-45.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/captenant-provider-upgraded-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-ready.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-45.initial.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/captenant-provider-upgraded-ready.yaml",
				"testdata/capapplication/cat-consumer-upg-never-deleting.yaml",
				"testdata/common/credential-secrets.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-31.initial.yaml",
				"testdata/capapplication/cav-name-modified-ready.yaml",
				"testdata/capapplication/cat-provider-no-finalizers-ready.yaml",
				"testdata/capapplication/cat-consumer-upgrading.yaml",
				"testdata/common/credential-secrets.yaml",
			},
			expectedResources: "testdata/capapplication/ca-31.expected.yaml",
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
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-virtualservices.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       false,
			expectedResources: "testdata/capapplication/ca-services-ready.yaml",
		},
	)
}

func TestCA_ServicesOnly_UpdatedHostDomains(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - updated host in domain",
			initialResources: []string{
				"testdata/common/domain-hostUpdated-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-virtualservices.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       false,
			expectedResources: "testdata/capapplication/ca-services-hostUpdated.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-ca-01"}}, ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-ca-01-cav-v1"}},
				ResourceDomain:        {{Namespace: "default", Name: "test-cap-01-primary"}},
				ResourceClusterDomain: {{Namespace: "", Name: "test-cap-01-secondary"}}},
		},
	)
}

func TestCA_ServicesOnly_NoDomainRef(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - no domain ref",
			initialResources: []string{
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-virtualservices.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:      []string{},
			expectError:       false,
			expectedResources: "testdata/capapplication/ca-processing-domainRefs.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplication: {{Namespace: "default", Name: "test-ca-01"}}},
		},
	)
}

func TestCA_ServicesOnly_Error(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplication, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-ca-01"}},
		TestData{
			description: "capapplication - services error case",
			initialResources: []string{
				"testdata/common/domain-ready.yaml",
				"testdata/common/cluster-domain-ready.yaml",
				"testdata/capapplication/ca-services.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/expected/cav-services-ready.yaml",
				"testdata/common/service-virtualservices.yaml",
				"testdata/capapplicationversion/services-ready.yaml",
				"testdata/capapplicationversion/service-content-job-completed.yaml",
			},
			backlogItems:          []string{},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "list", Group: "networking.istio.io", Version: "v1", Resource: "virtualservices", Namespace: "*", Name: "*"}},
		},
	)
	if err.Error() != "mocked api error (virtualservices.networking.istio.io/v1)" {
		t.Error("error message is different from expected: ", err.Error())
	}

}
