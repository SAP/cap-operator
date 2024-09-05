/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"testing"
)

func TestCAV_WithoutCAPApplicationAndVersion(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description:            "capapplication version with invalid capapplication and deleted capapplicationversion reference",
			expectResourceNotFound: true,
			expectError:            false, //No errors when no CAV to skip requeues
		},
	)
}

func TestCAV_WithoutCAPApplication(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description:      "capapplication version with invalid capapplication reference",
			initialResources: []string{"testdata/capapplicationversion/cav-invalid-ca.yaml"},
			expectError:      true,
		},
	)
}

func TestCAV_MissingSecrets(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with missing secrets",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/capapplicationversion/cav-empty-status.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-missing-secrets.yaml",
			expectError:       false, // CAV is requeued
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3351",
			},
		},
	)
}

func TestCAV_EmptyStatusProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with empty status",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-empty-status.yaml",
				"testdata/capapplicationversion/content-job-pending.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-processing.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_ErrorStatusProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with error (e.g. api-server error) status to processing",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-error-status.yaml",
				"testdata/capapplicationversion/content-job-pending.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-error-processing.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_ErrorWithConditionStatusProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with unknown error condition (e.g. api-server error) status to processing",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-error-condition-status.yaml",
				"testdata/capapplicationversion/content-job-pending.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-error-condition-processing.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_ContentJobMissing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with content job missing",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-waiting.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_ContentJobPending(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with pending content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing.yaml",
				"testdata/capapplicationversion/content-job-pending.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-waiting.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_ContentJobFailed(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with failed content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing.yaml",
				"testdata/capapplicationversion/content-job-failed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-content-job.yaml",
			expectError:       true,
		},
	)
}

func TestCAV_ContentJobFailedReconcilation(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "Reconcile error capapplication version with failed content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-failed-content-job.yaml",
				"testdata/capapplicationversion/content-job-failed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-content-job.yaml",
			expectError:       true,
		},
	)
}

func TestCAV_ContentJobCompletedFromProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with completed content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-content-job.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_OneOfMultipleContentJobsCompleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with one of the multiple content jobs completed",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-with-multiple-content-jobs.yaml",
				"testdata/capapplicationversion/one-of-mulitple-content-job-completed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-processing-with-multiple-content-jobs.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-4351",
			},
		},
	)
}

func TestCAV_AllMultipleContentJobsCompleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with all multiple content jobs completed",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-with-multiple-content-jobs.yaml",
				"testdata/capapplicationversion/all-mulitple-content-job-completed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-with-multiple-content-jobs.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-4351",
			},
		},
	)
}

func TestCAV_OneOfMultipleContentJobsfailed(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with one of the multiple content jobs failed",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-with-multiple-content-jobs.yaml",
				"testdata/capapplicationversion/one-of-mulitple-content-job-failed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-with-multiple-content-jobs.yaml",
			expectError:       true,
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-4351",
			},
		},
	)
}

func TestCAV_WithNoContentJob(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with no content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-with-no-content-job.yaml",
				"testdata/capapplicationversion/deployments-ready.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-with-no-content-job.yaml",
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-4351",
			},
		},
	)
}

func TestCAV_ContentJobCompletedExisting(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with completed content job",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-job-finished.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-content-job.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_InvalidEnvConfigContent(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with invalid content env config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-invalid-env-content.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-env-content.yaml",
			expectError:       true,
		},
	)
}

func TestCAV_WithRouterDestinationsEnv(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with merged router env config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-merged-destinations-router.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-merged-destinations-router.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3386", // merge existing `destinations` operator workload configuration by just overwriting the URL!
			},
		},
	)
}

func TestCAV_InvalidEnvConfigCAPServer(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with invalid cap server env config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-invalid-env-cap.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-env-cap.yaml",
			expectError:       true,
		},
	)
}

func TestCAV_InvalidEnvConfigJobWorker(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with invalid job worker env config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-invalid-env-job-worker.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-failed-env-job-worker.yaml",
			expectError:       true,
		},
	)
}

func TestCAV_ValidEnvConfigOverall(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with valid overall env config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-valid-env-config.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-valid-env-config.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2048", // Overall the generic workloads should run fine with this change
				"ERP4SMEPREPWORKAPPPLAT-3226", // imagePullPolicy
			},
		},
	)
}

func TestCAV_CustomLabels(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with valid overall config with custom labels",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-custom-labels.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-custom-labels-config.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2187", // Custom labels also tested here
			},
		},
	)
}

func TestCAV_CustomDestinationConfig(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with custom destination config",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-custom-destination-config.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-custom-destination-config.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-1843",
			},
		},
	)
}

func TestCAV_DeletingWithReadyTenants(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication deleting with valid ready tenants",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/common/captenant-provider-ready.yaml",
				"testdata/capapplicationversion/cav-ready-deleting.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-deleting.yaml",
			expectError:       false, // cav is requeued until dependents are gone
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_DeletingWithUpgradingVersionTenants(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication deleting with valid upgrading (version dependent) tenants",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cat-provider-version.yaml",
				"testdata/capapplicationversion/cav-ready-deleting.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-deleting.yaml",
			expectError:       false, // cav is requeued until dependents are gone
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
		},
	)
}

func TestCAV_DeletedWithNoTenants(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication deleting with no relevant tenants",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-ready-deleting.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-deleted.yaml", //finalizers removed
		},
	)
}

func TestCAV_DeletedWithUnknownStatusNoFinalizers(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication deleting with unknown status and no finalizers",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cat-provider-version.yaml",
				"testdata/capapplicationversion/cav-unknown-deleting.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-deleted-unknown.yaml", //finalizers not existing
		},
	)
}

func TestCAV_ProbesResources(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with probes and resources",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-probes-and-resources.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-probes-and-resources.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2237", // Probes and resources should be applied to deployments and jobs
			},
		},
	)
}

func TestCAV_AppNetworkPolicy(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with default network policies",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-probes-and-resources.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-app-netpol.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2638", // Default network policy w/o cluster type ports
				"ERP4SMEPREPWORKAPPPLAT-2707", //No N/w policies exist
				"ERP4SMEPREPWORKAPPPLAT-2707", // Split n/w policies
			},
		},
	)
}

func TestCAV_ClusterPortNetworkPolicy(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with cluster network policy ports",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-cluster-netpol-port.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-cluster-netpol-port.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2638", // Network policy for cluster-wide "tech" ports
				"ERP4SMEPREPWORKAPPPLAT-2707", // No fallback cluster network policy
				"ERP4SMEPREPWORKAPPPLAT-2707", // Split n/w policies
			},
		},
	)
}

func TestCAV_SecurityContext(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with container security context",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-security-context.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-security-context.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2573", // Security Context for containers
			},
		},
	)
}

func TestCAV_PodSecurityContext(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with pod security context",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-pod-security-context.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-pod-security-context.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2573", // Security Context for containers
			},
		},
	)
}

func TestCAV_Annotations(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with annotations",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-annotations.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-annotations.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-2885", // Annotations supported
			},
		},
	)
}

func TestCAV_NodeSelector(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with node selector",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-node-selector.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-node-selector.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3294", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_Affinity(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with affinity",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-affinity.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-affinity.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3294", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_TopologySpreadConstraints(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with topology spread constraints",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-topology.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-topology.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3294", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_Tolerations(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with tolerations",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-toleration.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-toleration.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3294", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_Node_PriorityClass_Names(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with nodeName and priorityClassName",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-node-prio.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-node-prio.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-3294", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_Volumes_and_ServiceAccountName(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with volumes and serviceAccountName",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-vol.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-vol.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-6370", // More workload configuration enhancements
			},
		},
	)
}

func TestCAV_InitContainers(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with initContainers",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/content-job-completed.yaml",
				"testdata/capapplicationversion/cav-init.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-ready-init.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceCAPApplicationVersion: {{Namespace: "default", Name: "test-cap-01-cav-v1"}}},
			backlogItems: []string{
				"ERP4SMEPREPWORKAPPPLAT-7450", //initContainers
			},
		},
	)
}

func TestCAV_DeploymentFailure(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceCAPApplicationVersion, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-cap-01-cav-v1"}},
		TestData{
			description: "capapplication version with failed deployment",
			initialResources: []string{
				"testdata/common/capapplication.yaml",
				"testdata/common/credential-secrets.yaml",
				"testdata/capapplicationversion/cav-processing-with-no-content-job.yaml",
				"testdata/capapplicationversion/deployments-failure.yaml",
			},
			expectedResources: "testdata/capapplicationversion/expected/cav-error-deployment-failure.yaml",
			expectError:       true,
		},
	)
}
