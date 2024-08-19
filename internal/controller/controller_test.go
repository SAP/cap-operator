/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/informers/batch"
	"k8s.io/client-go/informers/internalinterfaces"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type dummyInformerFactoryType struct {
	informers.SharedInformerFactory
	namespace        string
	tweakListOptions func(*metav1.ListOptions)
}

func (f *dummyInformerFactoryType) WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool {
	//Simulate error
	return map[reflect.Type]bool{reflect.TypeOf(metav1.TypeMeta{}): false}
}

func (f *dummyInformerFactoryType) Batch() batch.Interface {
	return f.SharedInformerFactory.Batch()
}

func (f *dummyInformerFactoryType) InformerFor(obj runtime.Object, newFunc internalinterfaces.NewInformerFunc) cache.SharedIndexInformer {
	return f.SharedInformerFactory.InformerFor(obj, newFunc)
}

func TestController_processQueue(t *testing.T) {
	tests := []struct {
		name              string
		resource          int
		resourceName      string
		resourceNamespace string
		earlyShutDown     bool
		expectError       bool
		errorString       string
	}{
		{
			name:              "Test Controller Start - process queue CAPApplication",
			resource:          ResourceCAPApplication,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       true,
			errorString:       "shutdown",
		},
		{
			name:        "Test Controller Start - process queue Unknown resource",
			resource:    9999,
			expectError: true,
			errorString: "unknown queue;",
		},
		{
			name:              "Test Controller Start - process queue CAPApplication - queue shutdown",
			resource:          ResourceCAPApplication,
			resourceName:      "test-ca",
			resourceNamespace: metav1.NamespaceDefault,
			earlyShutDown:     true,
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := getTestController(testResources{preventStart: true})

			dummyKubeInformerFactory := &dummyInformerFactoryType{c.kubeInformerFactory, tt.resourceNamespace, nil}

			testC := &Controller{
				kubeClient:                  c.kubeClient,
				crdClient:                   c.crdClient,
				istioClient:                 c.istioClient,
				gardenerCertificateClient:   c.gardenerCertificateClient,
				gardenerDNSClient:           c.gardenerDNSClient,
				kubeInformerFactory:         dummyKubeInformerFactory,
				crdInformerFactory:          c.crdInformerFactory,
				istioInformerFactory:        c.istioInformerFactory,
				gardenerCertInformerFactory: c.gardenerCertInformerFactory,
				gardenerDNSInformerFactory:  c.gardenerDNSInformerFactory,
				queues:                      c.queues,
				eventBroadcaster:            c.eventBroadcaster,
				eventRecorder:               events.NewFakeRecorder(10),
			}

			// Create a background context that gets cancelled once the test run completes
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			testC.Start(ctx)

			// Manual API checks
			var expectedRes error
			if tt.earlyShutDown {
				expectedRes = testC.processQueue(ctx, tt.resource)
			} else {
				expectedRes = testC.processQueue(context.TODO(), tt.resource)
			}

			if !tt.expectError && expectedRes != nil {
				t.Error("Unexpected result", expectedRes)
			} else if tt.expectError && expectedRes == nil {
				t.Error("Unexpected result", "error is nil")
			} else if tt.expectError && expectedRes != nil {
				res := strings.Count(expectedRes.Error(), tt.errorString)
				if res < 1 {
					t.Error("Unexpected result", expectedRes, "; expected to contain", tt.errorString)
				}
			}
		})
	}
}

func TestController_processQueueItem(t *testing.T) {
	tests := []struct {
		name              string
		createCA          bool
		createCAPTenant   bool
		resource          int
		resourceName      string
		resourceNamespace string
		earlyShutDown     bool
		expectError       bool
		errorString       string
		expectRequeue     bool
	}{
		{
			name:              "Test Controller Start - process queue item CAPApplication",
			resource:          ResourceCAPApplication,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:              "Test Controller Start - process queue item CAPApplication (Requeue)",
			createCA:          true,
			resource:          ResourceCAPApplication,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:              "Test Controller Start - process queue item CAPApplicationVersion",
			resource:          ResourceCAPApplicationVersion,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:              "Test Controller Start - process queue item CAPTenant",
			resource:          ResourceCAPTenant,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:              "Test Controller Start - process queue item CAPTenantOperation",
			resource:          ResourceCAPTenantOperation,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:              "Test Controller Start - process queue item unidentified queue item",
			resource:          9,
			resourceName:      "test-res",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
		},
		{
			name:        "Test Controller Start - process queue item Unknown item",
			resource:    99,
			expectError: false,
		},
		{
			name:        "Test Controller Start - process queue item Unknown resource",
			resource:    999,
			expectError: true,
			errorString: "unknown queue;",
		},
		{
			name:              "Test Controller Start - process queue item CAPApplication - queue shutdown",
			resource:          ResourceCAPApplication,
			resourceName:      "test-ca",
			resourceNamespace: metav1.NamespaceDefault,
			earlyShutDown:     true,
			expectError:       true,
			errorString:       "shutdown",
		},
		{
			name:              "Test Controller Start - process queue item CAPTenant - reconciliation error and requeue",
			createCAPTenant:   true,
			resource:          ResourceCAPTenant,
			resourceName:      "ca-does-not-exist-provider",
			resourceNamespace: metav1.NamespaceDefault,
			expectError:       false,
			expectRequeue:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				ca  *v1alpha1.CAPApplication
				cat *v1alpha1.CAPTenant
			)
			if tt.createCA {
				ca = createCaCRO(tt.resourceName, true)
			}
			if tt.createCAPTenant {
				cat = createCatCRO("ca-does-not-exist", "provider", true)
			}

			c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}, cats: []*v1alpha1.CAPTenant{cat}, preventStart: true})
			if tt.resource == 9 || tt.resource == 99 {
				c.queues[tt.resource] = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
			}

			dummyKubeInformerFactory := &dummyInformerFactoryType{c.kubeInformerFactory, tt.resourceNamespace, nil}

			testC := &Controller{
				kubeClient:                  c.kubeClient,
				crdClient:                   c.crdClient,
				istioClient:                 c.istioClient,
				gardenerCertificateClient:   c.gardenerCertificateClient,
				gardenerDNSClient:           c.gardenerDNSClient,
				kubeInformerFactory:         dummyKubeInformerFactory,
				crdInformerFactory:          c.crdInformerFactory,
				istioInformerFactory:        c.istioInformerFactory,
				gardenerCertInformerFactory: c.gardenerCertInformerFactory,
				gardenerDNSInformerFactory:  c.gardenerDNSInformerFactory,
				queues:                      c.queues,
			}

			// Create a background context that gets cancelled once the test run completes
			ctx, cancel := context.WithCancel(context.Background())

			item := QueueItem{Key: tt.resource, ResourceKey: NamespacedResourceKey{Namespace: tt.resourceNamespace, Name: tt.resourceName}}

			q := c.queues[tt.resource]

			// Manual API checks
			var expectedRes error
			if tt.earlyShutDown {
				q.ShutDown()
				cancel()
				expectedRes = testC.processQueueItem(ctx, tt.resource)
			} else {
				if tt.resource < 4 || tt.resource == 9 {
					q.Add(item)
				} else if tt.resource == 99 {
					q.Add(tt.resource)
				}
				expectedRes = testC.processQueueItem(context.TODO(), tt.resource)
			}

			if !tt.expectError && expectedRes != nil {
				t.Error("Unexpected result", expectedRes)
			} else if tt.expectError && expectedRes == nil {
				t.Error("Unexpected result", "error is nil")
			} else if tt.expectError && expectedRes != nil {
				res := strings.Count(expectedRes.Error(), tt.errorString)
				if res < 1 {
					t.Error("Unexpected result", expectedRes, "; expected to contain", tt.errorString)
				} else {
					klog.InfoS("Expected error occurred", "result", expectedRes, "expected result", tt.errorString)
				}
			} else {
				if tt.expectRequeue {
					if q.NumRequeues(item) < 1 {
						t.Errorf("expected item to be requeued after reconciliation error")
					}
				}
			}
			cancel()
		})
	}
}

func TestController_recoverFromPanic(t *testing.T) {
	var resourceName = "test-res"
	var catType = "provider"
	tests := []struct {
		name              string
		resource          int
		resourceName      string
		resourceNamespace string
		expectPanic       bool
		catUpgrading      bool
	}{
		{
			name:              "Test Controller recoverFromPanic - no panic in CAPApplication",
			resource:          ResourceCAPApplication,
			resourceName:      resourceName,
			resourceNamespace: metav1.NamespaceDefault,
			expectPanic:       false,
		},
		{
			name:              "Test Controller recoverFromPanic - panic in CAPApplication",
			resource:          ResourceCAPApplication,
			resourceName:      resourceName,
			resourceNamespace: metav1.NamespaceDefault,
			expectPanic:       true,
		},
		{
			name:              "Test Controller recoverFromPanic - panic in CAPApplicationVersion",
			resource:          ResourceCAPApplicationVersion,
			resourceName:      resourceName,
			resourceNamespace: metav1.NamespaceDefault,
			expectPanic:       true,
		},
		{
			name:              "Test Controller recoverFromPanic - panic in provisioning CAPTenant",
			resource:          ResourceCAPTenant,
			resourceName:      resourceName + "-" + catType,
			resourceNamespace: metav1.NamespaceDefault,
			expectPanic:       true,
		},
		{
			name:              "Test Controller recoverFromPanic - panic in upgrading CAPTenant",
			resource:          ResourceCAPTenant,
			resourceName:      resourceName + "-" + catType,
			resourceNamespace: metav1.NamespaceDefault,
			catUpgrading:      true,
			expectPanic:       true,
		},
		{
			name:              "Test Controller recoverFromPanic - panic in CAPTenantOperation",
			resource:          ResourceCAPTenantOperation,
			resourceName:      resourceName,
			resourceNamespace: metav1.NamespaceDefault,
			expectPanic:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				ca   *v1alpha1.CAPApplication
				cav  *v1alpha1.CAPApplicationVersion
				cat  *v1alpha1.CAPTenant
				ctop *v1alpha1.CAPTenantOperation
			)

			ca = createCaCRO(tt.resourceName, true)
			cav = createCavCRO(tt.resourceName, "", "0.0.1")
			cat = createCatCRO(resourceName, catType, true)
			if tt.catUpgrading {
				cat.Status.State = v1alpha1.CAPTenantStateUpgrading
			} else {
				cat.Status.State = v1alpha1.CAPTenantStateProvisioning
			}
			ctop = &v1alpha1.CAPTenantOperation{
				ObjectMeta: metav1.ObjectMeta{Name: tt.resourceName, Namespace: tt.resourceNamespace},
				Spec:       v1alpha1.CAPTenantOperationSpec{},
				Status: v1alpha1.CAPTenantOperationStatus{
					GenericStatus: v1alpha1.GenericStatus{},
					State:         "",
				},
			}

			c := getTestController(testResources{cas: []*v1alpha1.CAPApplication{ca}, cavs: []*v1alpha1.CAPApplicationVersion{cav}, cats: []*v1alpha1.CAPTenant{cat}, ctops: []*v1alpha1.CAPTenantOperation{ctop}, preventStart: true})
			dummyKubeInformerFactory := &dummyInformerFactoryType{c.kubeInformerFactory, tt.resourceNamespace, nil}

			testC := &Controller{
				kubeClient:                  c.kubeClient,
				crdClient:                   c.crdClient,
				istioClient:                 c.istioClient,
				gardenerCertificateClient:   c.gardenerCertificateClient,
				gardenerDNSClient:           c.gardenerDNSClient,
				kubeInformerFactory:         dummyKubeInformerFactory,
				crdInformerFactory:          c.crdInformerFactory,
				istioInformerFactory:        c.istioInformerFactory,
				gardenerCertInformerFactory: c.gardenerCertInformerFactory,
				gardenerDNSInformerFactory:  c.gardenerDNSInformerFactory,
				queues:                      c.queues,
			}

			// Create a background context that gets cancelled once the test run completes
			ctx, cancel := context.WithCancel(context.Background())

			item := QueueItem{Key: tt.resource, ResourceKey: NamespacedResourceKey{Namespace: tt.resourceNamespace, Name: tt.resourceName}}

			q := c.queues[tt.resource]

			defer testC.recoverFromPanic(ctx, item, q)

			defer cancel()

			if tt.expectPanic {
				panic("Simulate some panic during reconcile")
			}

			// There is no need to check for results in this test as in case of errros the panic raised above will not be reovered!
		})
	}

}
