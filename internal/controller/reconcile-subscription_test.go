/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

func TestSubscriptionStateTransitionToProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-01"}},
		TestData{
			description:       "subscription with empty state transitions to Processing",
			initialResources:  []string{"testdata/subscription/sub-01.initial.yaml"},
			expectedResources: "testdata/subscription/sub-01.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-01"},
				},
			},
		},
	)
}

func TestSubscriptionCAPApplicationNotFound(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-02"}},
		TestData{
			description:       "subscription in Processing with no matching CAPApplication → ApplicationError",
			initialResources:  []string{"testdata/subscription/sub-02.initial.yaml"},
			expectedResources: "testdata/subscription/sub-02.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionInvalidSpecDomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-03"}},
		TestData{
			description:       "subscription with unresolvable spec.subscriptionDomain → URLError",
			initialResources:  []string{"testdata/subscription/sub-03.initial.yaml"},
			expectedResources: "testdata/subscription/sub-03.expected.yaml",
		},
	)
}

func TestSubscriptionCreateTenantFromSpecDomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-04"}},
		TestData{
			description:       "subscription with valid spec.subscriptionDomain (Domain) creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-04.initial.yaml"},
			expectedResources: "testdata/subscription/sub-04.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-04"},
				},
			},
		},
	)
}

func TestSubscriptionCreateTenantFromCAAnnotationDomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-05"}},
		TestData{
			description:       "subscription domain from CAPApplication annotation (ClusterDomain) creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-05.initial.yaml"},
			expectedResources: "testdata/subscription/sub-05.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-05"},
				},
			},
		},
	)
}

func TestSubscriptionCreateTenantFromPrimaryDomainRef(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-06"}},
		TestData{
			description:       "subscription domain from primary DomainRef (Domain) creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-06.initial.yaml"},
			expectedResources: "testdata/subscription/sub-06.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-06"},
				},
			},
		},
	)
}

func TestSubscriptionCreateTenantFromPrimaryClusterDomainRef(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-07"}},
		TestData{
			description:       "subscription domain from primary ClusterDomainRef creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-07.initial.yaml"},
			expectedResources: "testdata/subscription/sub-07.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-07"},
				},
			},
		},
	)
}

func TestSubscriptionWaitsForTenantProvisioning(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-08"}},
		TestData{
			description:       "subscription waits for existing CAPTenant still Provisioning",
			initialResources:  []string{"testdata/subscription/sub-08.initial.yaml"},
			expectedResources: "testdata/subscription/sub-08.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-08"},
				},
			},
		},
	)
}

func TestSubscriptionTenantProvisioningError(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-09"}},
		TestData{
			description:       "subscription transitions to Error when CAPTenant is in ProvisioningError",
			initialResources:  []string{"testdata/subscription/sub-09.initial.yaml"},
			expectedResources: "testdata/subscription/sub-09.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionReadyWhenTenantReady(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-10"}},
		TestData{
			description:       "subscription transitions to Ready when CAPTenant is ready",
			initialResources:  []string{"testdata/subscription/sub-10.initial.yaml"},
			expectedResources: "testdata/subscription/sub-10.expected.yaml",
		},
	)
}

func TestSubscriptionNotFound(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-notfound"}},
		TestData{
			description:            "subscription not found in store is handled without error",
			expectResourceNotFound: true,
		},
	)
}

func TestSubscriptionGUIDLabelSync(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-12"}},
		TestData{
			description:       "subscription with missing GUID label gets label updated and transitions to Processing",
			initialResources:  []string{"testdata/subscription/sub-12.initial.yaml"},
			expectedResources: "testdata/subscription/sub-12.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-12"},
				},
			},
		},
	)
}

func TestSubscriptionTenantUpgradeError(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-13"}},
		TestData{
			description:       "subscription transitions to Error when CAPTenant is in UpgradeError",
			initialResources:  []string{"testdata/subscription/sub-13.initial.yaml"},
			expectedResources: "testdata/subscription/sub-13.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionProcessingWithExistingProvisioningErrorTenantRequeue(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-14"}},
		TestData{
			description:       "subscription in empty state with existing ProvisioningError CAPTenant requeues both Subscription and CAPTenant",
			initialResources:  []string{"testdata/subscription/sub-14.initial.yaml"},
			expectedResources: "testdata/subscription/sub-14.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-14"},
				},
				ResourceCAPTenant: {
					{Namespace: "default", Name: "test-sub-14-tenant"},
				},
			},
		},
	)
}

func TestSubscriptionCreateTenantFromSpecDomainClusterDomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-15"}},
		TestData{
			description:       "subscription with valid spec.subscriptionDomain (ClusterDomain) creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-15.initial.yaml"},
			expectedResources: "testdata/subscription/sub-15.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-15"},
				},
			},
		},
	)
}

func TestSubscriptionCreateTenantFromCAAnnotationDomainNamespace(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-16"}},
		TestData{
			description:       "subscription domain from CAPApplication annotation (namespace Domain) creates CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-16.initial.yaml"},
			expectedResources: "testdata/subscription/sub-16.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-16"},
				},
			},
		},
	)
}

func TestSubscriptionEmptyDomainRefsCreatesTenantWithEmptyDomain(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-17"}},
		TestData{
			description:       "subscription with no spec domain, no CA annotation and no domainRefs transitions to Error with URLError",
			initialResources:  []string{"testdata/subscription/sub-17.initial.yaml"},
			expectedResources: "testdata/subscription/sub-17.expected.yaml",
		},
	)
}

func TestSubscriptionDeletionWaitsForTenantBeingDeleted(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-18"}},
		TestData{
			description:       "subscription being deleted waits while CAPTenant still has deletionTimestamp",
			initialResources:  []string{"testdata/subscription/sub-18.initial.yaml"},
			expectedResources: "testdata/subscription/sub-18.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-18"},
				},
			},
		},
	)
}

func TestSubscriptionDeletionFinalizerRemovedWhenTenantGone(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-19"}},
		TestData{
			description:       "subscription being deleted removes finalizer once CAPTenant is gone",
			initialResources:  []string{"testdata/subscription/sub-19.initial.yaml"},
			expectedResources: "testdata/subscription/sub-19.expected.yaml",
		},
	)
}

func TestSubscriptionDeletionTriggersTenantDelete(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscription, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-sub-20"}},
		TestData{
			description:       "subscription being deleted triggers Delete on existing CAPTenant and requeues",
			initialResources:  []string{"testdata/subscription/sub-20.initial.yaml"},
			expectedResources: "testdata/subscription/sub-20.expected.yaml",
			expectedRequeue: map[int][]NamespacedResourceKey{
				ResourceSubscription: {
					{Namespace: "default", Name: "test-sub-20"},
				},
			},
		},
	)
}

// Compile-time check that v1alpha1 is used
var _ = v1alpha1.SubscriptionStateReady
