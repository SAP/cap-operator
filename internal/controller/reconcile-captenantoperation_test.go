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

func TestPrepareCAPTenantOperationProvisioning(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136", "ERP4SMEPREPWORKAPPPLAT-3351"},
			description:  "new captenantoperation type provisioning - prepare",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-01.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-01.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestTenantOperationInitializeStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - initialize current step",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-02.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-02.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestTenantOperationWithNoSteps(t *testing.T) {
	// Env set for this test to enable coverage for detailed metrics --> this has no impact on tenant operation code/test as such.
	detailedMetrics := "DETAILED_OPERATIONAL_METRICS"
	defer os.Unsetenv(detailedMetrics)
	os.Setenv(detailedMetrics, "true")
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation w/o valid capapplicationversion",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-03.initial.yaml",
			},
			expectError:       true,
			expectedResources: "testdata/captenantoperation/ctop-03.expected.yaml",
		},
	)
	if err.Error() != "operation steps missing in CAPTenantOperation default.test-cap-01-provider-abcd" {
		t.Error("unexpected error")
	}
}

func TestTenantOperationStepProcessingWithoutVersion(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - initialize current step",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-04.initial.yaml",
			},
			expectError: true,
		},
	)
	if err.Error() != "capapplicationversions.sme.sap.com \"test-cap-01-cav-v1\" not found" {
		t.Error("unexpected error")
	}
}

func TestProvisioningOperationTriggerStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - initialize current step",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-04.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-04.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestPrepareCAPTenantOperationUpgrade(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "new captenantoperation type upgrade - prepare",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-05.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-05.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationDeriveFromCAPWorkload(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - tenant operation step deriving from cap workload",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-no-mtx-workload.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-06.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-06.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsInitiateFirstStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136", "ERP4SMEPREPWORKAPPPLAT-3226"},
			description:  "prepared captenantoperation - multiple steps - start custom operation",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-07.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-07.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsStepCompleted(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136", "ERP4SMEPREPWORKAPPPLAT-3226"},
			description:  "prepared captenantoperation - multiple steps - custom step completed",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-08.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-08.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsInitiateSubsequentStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - multiple steps - initiate subsequent step",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-09.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-09.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsStepFailure(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - multiple steps - step failure",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-10.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-10.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsFinalStepCompleted(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - multiple steps - final step completed",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-11.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-11.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsStepCompletedWithDeletion(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - multiple steps - custom step completed with deletion timestamp set",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-12.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-12.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationMultipleStepsStepFailureWithDeletion(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - multiple steps - step failure with deletion timestamp set",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-13.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-13.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeOperationFailedWithDeletion(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation - failed condition - with deletion timestamp set",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multiple-tenant-ops.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-14.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-14.expected.yaml",
		},
	)
}

func TestPrepareCAPTenantOperationDeprovisioningInvalidReference(t *testing.T) {
	err := reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-invalid-tenant-op"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "new captenantoperation type deprovisioning - prepare with invalid reference",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-15.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-15.expected.yaml",
			expectError:       true,
		},
	)
	if err.Error() != "could not find CAPTenant with tenant id tenant-id-invalid" {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestTenantOperationDeprovisioningInitiateStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "prepared captenantoperation type deprovisioning - initiate step processing",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-16.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-16.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestTenantOperationDeprovisioningTrackStep(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2136"},
			description:  "captenantoperation type deprovisioning - track step progress",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-17.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-17.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithMTXSEnabled(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2236", "ERP4SMEPREPWORKAPPPLAT-2379", "ERP4SMEPREPWORKAPPPLAT-3226", "ERP4SMEPREPWORKAPPPLAT-3807"},
			description:  "Provisioning - With MTXS enabled",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-mtxs.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-18.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-18.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestUpgradeWithMTXSEnabled(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2379", "ERP4SMEPREPWORKAPPPLAT-3226", "ERP4SMEPREPWORKAPPPLAT-3807"},
			description:  "Upgrade - With MTXS enabled",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-mtxs.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-20.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-20.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestDeprovisioningWithMTXSEnabled(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2236", "ERP4SMEPREPWORKAPPPLAT-2379", "ERP4SMEPREPWORKAPPPLAT-3226", "ERP4SMEPREPWORKAPPPLAT-3807"},
			description:  "Deprovisioning - With MTXS enabled",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/capapplicationversion-v1-mtxs.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/captenantoperation/ctop-19.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-19.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithMTXSEnabledAndCustomCommand(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2747", // Custom command for Tenant Operation
				"ERP4SMEPREPWORKAPPPLAT-2885", // Annotations for Tenant Operation
				"ERP4SMEPREPWORKAPPPLAT-3807", // MTXS is made default
			},
			description: "Provisioning - With MTXS enabled and custom command",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-mtxs-custom-cmd.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-24.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-24.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithResources(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2237"},
			description:  "Provisioning - With Resources",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-resources.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-21.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-21.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithSecurityContext(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2573"},
			description:  "Provisioning - With securityContext for Container",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-security-context.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-22.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-22.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithPodSecurityContext(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2573"},
			description:  "Provisioning - With securityContext for Pod",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-pod-security-context.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-23.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-23.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithAnnotations(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2885"},
			description:  "Provisioning - With annotations",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-annotations.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-25.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-25.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestMultiXSUAAWithAnnotation(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-3773"},
			description:  "prepared captenantoperation - tenant operation with multiple xsuaa usage",
			initialResources: []string{
				"testdata/common/capapplication-multi-xsuaa.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v2-multi-xsuaa.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-26.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-26.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithSchedulingConfig(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-3294"}, // More workload configuration enhancements
			description:  "Provisioning - With scheduling config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-scheduling.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-scheduling.initial.yaml", // The config in there might not make sense in the real world!
			},
			expectedResources: "testdata/captenantoperation/ctop-scheduling.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithSchedulingConfigCustom(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-3294"}, // More workload configuration enhancements
			description:  "Provisioning - With scheduling config for CustomTenantOperation",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-scheduling-custom.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-scheduling-custom.initial.yaml", // The config in there might not make sense in the real world!
			},
			expectedResources: "testdata/captenantoperation/ctop-scheduling-custom.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithVolAndServiceAccountName(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-6370"}, // More workload configuration enhancements
			description:  "Provisioning - With volume and service account config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-vol.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-vol.initial.yaml", // The config in there might not make sense in the real world!
			},
			expectedResources: "testdata/captenantoperation/ctop-vol.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithVolumeAndServiceAccountNameCustom(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-6370"}, // More workload configuration enhancements
			description:  "Provisioning - With volume and serviceAccountName config for CustomTenantOperation",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-vol-custom.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-vol-custom.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-vol-custom.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithInitContainers(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-7450"}, // initContainers for Tenant Operation
			description:  "Provisioning - With initContainers for TenantOperation",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-init.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-init.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-init.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}

func TestProvisioningWithInitContainersCustom(t *testing.T) {
	_ = reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPTenantOperation, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
		TestData{
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-7450"}, // initContainers for Custom Tenant Operation
			description:  "Provisioning - With initContainers for CustomTenantOperation",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/common/capapplicationversion-v1-init-custom.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/captenantoperation/ctop-init-custom.initial.yaml",
			},
			expectedResources: "testdata/captenantoperation/ctop-init-custom.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceCAPTenantOperation: {{Namespace: "default", Name: "test-cap-01-provider-abcd"}},
			},
		},
	)
}
