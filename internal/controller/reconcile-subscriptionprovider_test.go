/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"testing"
)

func TestSubscriptionProviderStateTransitionToProcessing(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-01"}},
		TestData{
			description: "SubscriptionProvider in empty state transitions to Processing and requeues",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-01.initial.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-01.expected.yaml",
			expectedRequeue:   map[int][]NamespacedResourceKey{ResourceSubscriptionProvider: {{Namespace: "default", Name: "test-subpro-01"}}},
		},
	)
}

func TestSubscriptionProviderNoOwningCAPApplication(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-02"}},
		TestData{
			description: "SubscriptionProvider in Processing state with no ownerReference transitions to Error",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-02.initial.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-02.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionProviderOwnerCAPApplicationNotFound(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-03"}},
		TestData{
			description: "SubscriptionProvider in Processing state with owner ref but CAPApplication missing in store transitions to Error",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-03.initial.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-03.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionProviderSecretNotFound(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-04"}},
		TestData{
			description: "SubscriptionProvider in Processing state with CAPApplication that references a missing secret transitions to Error",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-04.initial.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-04.expected.yaml",
			expectError:       true,
		},
	)
}

func TestSubscriptionProviderNoDependencies(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-05"}},
		TestData{
			description: "SubscriptionProvider with CAPApplication whose only service (xsuaa) is not a subscription dependency - resolves to Ready with empty dependencies",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-05.initial.yaml",
				"testdata/subscriptionprovider/credential-secrets.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-05.expected.yaml",
		},
	)
}

func TestSubscriptionProviderSaaSRegistryDependency(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-06"}},
		TestData{
			description: "SubscriptionProvider with CAPApplication using saas-registry (saasregistryenabled=true) - resolves to Ready with xsappname dependency",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-06.initial.yaml",
				"testdata/subscriptionprovider/credential-secrets.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-06.expected.yaml",
		},
	)
}

func TestSubscriptionProviderDestinationSpecialDependency(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-07"}},
		TestData{
			description: "SubscriptionProvider with CAPApplication using destination service - resolves to Ready with appName/appId special dependency format",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-07.initial.yaml",
				"testdata/subscriptionprovider/credential-secrets.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-07.expected.yaml",
		},
	)
}

func TestSubscriptionProviderMixedDependencies(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-08"}},
		TestData{
			description: "SubscriptionProvider with CAPApplication containing mixed services (xsuaa, saas-registry, destination, service-manager) - resolves to Ready with saas and destination dependencies",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-08.initial.yaml",
				"testdata/subscriptionprovider/credential-secrets.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-08.expected.yaml",
		},
	)
}

func TestSubscriptionProviderAlwaysDependency(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-09"}},
		TestData{
			description: "SubscriptionProvider with CAPApplication service marked SubscriptionDependencyAlways - included regardless of credential content",
			initialResources: []string{
				"testdata/subscriptionprovider/subpro-09.initial.yaml",
				"testdata/subscriptionprovider/credential-secrets.yaml",
			},
			expectedResources: "testdata/subscriptionprovider/subpro-09.expected.yaml",
		},
	)
}

func TestSubscriptionProviderNotFound(t *testing.T) {
	reconcileTestItem(
		context.TODO(), t,
		QueueItem{Key: ResourceSubscriptionProvider, ResourceKey: NamespacedResourceKey{Namespace: "default", Name: "test-subpro-missing"}},
		TestData{
			description:            "SubscriptionProvider not found in store - reconciliation skipped without error",
			initialResources:       []string{},
			expectResourceNotFound: true,
		},
	)
}
