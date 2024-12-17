/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"os"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

func TestInvalidCAPApplication(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description:      "new captenant with invalid capapplication reference",
			initialResources: []string{"testdata/captenant/cat-01.initial.yaml"},
			expectError:      true,
		},
	)
}

func TestLabelsOwnerRefs(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-consumer"}},
		TestData{
			description:       "new captenant without labels, finalizers and owner references",
			initialResources:  []string{"testdata/common/capapplication.yaml", "testdata/captenant/cat-02.initial.yaml"},
			expectedResources: "testdata/captenant/cat-02.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Name: "test-cap-01-consumer", Namespace: "default"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3351",
			},
		},
	)
}

func TestWithoutSpecVersion(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-consumer"}},
		TestData{
			description:       "new captenant with labels, finalizers and owner references and no version in spec",
			initialResources:  []string{"testdata/common/capapplication.yaml", "testdata/captenant/cat-with-no-version.yaml"},
			expectedResources: "testdata/captenant/cat-with-no-version.yaml",
		},
	)
}

func TestInvalidVersion(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-consumer"}},
		TestData{
			description: "new captenant with invalid version",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/captenant/cat-14.initial.yaml",
			},
			expectError: true,
		},
	)

	if err.Error() != "could not find a CAPApplicationVersion with status Ready for CAPApplication default.test-cap-01 and version 5.6.7" {
		t.Error("error message did not match expected")
	}
}

func TestCAPTenantStartProvisioning(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-consumer"}},
		TestData{
			description: "new captenant start provisioning (with secondary domains)",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-03.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-03.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-consumer"}}},
		},
	)
}

func TestCAPTenantProvisioningCompletedDNSEntriesNotReady(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation completed dns entries not ready",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/provider-tenant-dnsentry-not-ready.yaml",
				"testdata/captenant/cat-04.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-04.initial.yaml", // expect the same resource state
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantProvisioningCompleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation completed (creates virtual service and destination rule)",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-04.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-04.expected.yaml",
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2811"},
		},
	)
}

func TestCAPTenantProvisioningCompletedDestinationRuleModificationFailure(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation completed (destination rule creation fails)",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-04.initial.yaml",
			},
			expectError:           true,
			mockErrorForResources: []ResourceAction{{Verb: "create", Group: "networking.istio.io", Version: "v1", Resource: "destinationrules", Namespace: "default", Name: "test-cap-01-provider"}},
			backlogItems:          []string{"ERP4SMEPREPWORKAPPPLAT-2811"},
		},
	)
	if err.Error() != "mocked api error (destinationrules.networking.istio.io/v1)" {
		t.Error("error message is different from expected")
	}
}

func TestCAPTenantProvisioningFailed(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation failed",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-05.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-05.expected.yaml",
		},
	)
}

func TestCAPTenantProvisioningRequestFailedWithInvalidEnv(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation failed due to invalid env (status reason)",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-invalid-env.yaml",
				"testdata/captenant/cat-26.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-05.expected.yaml",
		},
	)
}

func TestCAPTenantProvisioningRequestDeleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant provisioning operation deleted while tenant is provisioning",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-20.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-20.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantWaitingForProvisioning(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant waiting for provisioning operation",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-06.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-06.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantStartUpgradeWithStrategyAlways(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant start upgrade from ready state with strategy always",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/cat-07.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-07.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantStartUpgradeWithStrategyNever(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant start upgrade from ready state with strategy never ",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/cat-08.initial.yaml",
				"testdata/captenant/provider-tenant-vs-v1.yaml",
				"testdata/captenant/provider-tenant-dr-v1.yaml",
			},
			expectedResources: "testdata/captenant/cat-08.expected.yaml",
		},
	)
}

func TestCAPTenantDeprovisioningFromReady(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant deprovisioning from ready",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/cat-09.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-09.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantDeprovisioningCompleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant deprovisioning completed",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-10.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-10.expected.yaml",
		},
	)
}

func TestCAPTenantDeprovisioningFromProvisioningError(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant deprovisioning from provisioning error",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/captenant/cat-11.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-11.expected.yaml",
		},
	)
}

func TestCAPTenantUpgradeOperationCompleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant upgrade operation completed expecting virtual service, destination rule adjustments",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/provider-tenant-vs-v1.yaml",
				"testdata/captenant/provider-tenant-dr-v1.yaml",
				"testdata/captenant/cat-13.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-13.expected.yaml",
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2811", "ERP4SMEPREPWORKAPPPLAT-3206"},
		},
	)
}

func TestCAPTenantUpgradeOperationCompletedPreviousVersionsLimited(t *testing.T) {
	os.Setenv(v1alpha1.EnvMaxTenantVersionHistory, "3")
	defer os.Unsetenv(v1alpha1.EnvMaxTenantVersionHistory)
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant upgrade operation completed expecting limited previous versions in status to be adjusted",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/provider-tenant-vs-v1.yaml",
				"testdata/captenant/provider-tenant-dr-v1.yaml",
				"testdata/captenant/cat-29.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-29.expected.yaml",
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-3206"},
		},
	)
}

func TestCAPTenantUpgradeRequestCompletedIncorrectVirtualServiceOwner(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant upgrade operation completed, existing virtual service owner wrong",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-22.initial.yaml",
			},
			expectError: true,
		},
	)
	if err.Error() != "invalid owner reference found for VirtualService default.test-cap-01-provider" {
		t.Error("wrong error message")
	}
}

func TestCAPTenantUpgradeRequestCompletedWithDeletionTriggered(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "captenant upgrade operation completed and deletion timestamp set",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-21.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-21.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantSubdomainChange(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "update captenant subdomain (no existing destination rule)",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/changed-provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-15.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-15.expected.yaml",
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2811"},
		},
	)
}

func TestAdjustVirtualServiceWithoutOperatorGateway(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "reconcile virtual service (subdomain change) when operator gateway is not ready",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/changed-provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-15.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-16.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantDNSEntryModified(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "reconcile DNS Entry (subdomain change) update from existing DNSEntry",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/to-be-updated-provider-tenant-dnsentry.yaml",
				"testdata/captenant/cat-17.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-17.expected.yaml",
			// DeleteCollection does not work for fake test client - the common_test framework currently mocks it by matching (only) labels
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-1817", "ERP4SMEPREPWORKAPPPLAT-2707", "ERP4SMEPREPWORKAPPPLAT-2811"},
		},
	)
}

func TestCAPTenantDNSEntryDeletedInCluster(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "reconcile DNS Entry (subdomain change) when existing DNSEntry was deleted in cluster",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/captenant/cat-15.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-17.expected.yaml",
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-1817", "ERP4SMEPREPWORKAPPPLAT-2707"},
		},
	)
}

func TestCAPTenantWithUpgradeErrorSameVersion(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "tenant in UpgradeError state, no spec update, failed mtxrequest exists - expect no new mtxrequest",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/operator-gateway.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/capapplicationversion-v3.yaml",
				"testdata/captenant/cat-23.initial.yaml",
				"testdata/captenant/provider-tenant-vs-v1.yaml",
				"testdata/captenant/provider-tenant-dr-v1.yaml",
			},
			expectedResources: "testdata/captenant/cat-23.expected.yaml",
		},
	)
}

func TestCAPTenantWithUpgradeErrorUpdatedVersion(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "tenant in UpgradeError state, spec version incremented, failed mtxrequest exists - expect new mtxrequest to be created",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/capapplicationversion-v3.yaml",
				"testdata/captenant/cat-24.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-24.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2977", // `Ready` condition stays `True` through upgrades
			},
		},
	)
}

func TestCAPTenantWithUpgradeErrorSameVersionMTXRequestRemoved(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			description: "tenant in UpgradeError state, no spec update, failed mtxrequest removed - expect new mtxrequest",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2.yaml",
				"testdata/common/capapplicationversion-v3.yaml",
				"testdata/captenant/cat-25.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-25.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantUpgradeWithoutTenantOperationWorkloadInVersion(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "captenant start upgrade deriving TenantOperation workload from CAP workload",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/capapplicationversion-v2-no-mtx-workload.yaml",
				"testdata/captenant/cat-07.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-27.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-provider"}}},
		},
	)
}

func TestCAPTenantStartProvisioningWithMultipleOperationSteps(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenant, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-consumer"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "captenant start provisioning with version containing multiple operation steps",
			initialResources: []string{
				"testdata/common/istio-ingress.yaml",
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/captenant/cat-28.initial.yaml",
			},
			expectedResources: "testdata/captenant/cat-28.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPTenant: {{Namespace: "default", Name: "test-cap-01-consumer"}}},
		},
	)
}
