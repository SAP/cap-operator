/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"testing"
	"time"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

var expectedResult = false

type dummyType struct {
	workqueue.TypedRateLimitingInterface[QueueItem]
}

func (q *dummyType) Add(item QueueItem) {
	expectedResult = true
}

func (q *dummyType) AddAfter(item QueueItem, duration time.Duration) {
	expectedResult = true
}

func TestController_initializeInformers(t *testing.T) {
	tests := []struct {
		name            string
		expectedResult  bool
		invalidOwnerRef bool
		res             int
		itemName        string
		itemNamespace   string
	}{
		{
			name:           "Test enqueueModifiedResource (ResourceCAPApplication)",
			res:            ResourceCAPApplication,
			expectedResult: true,
			itemName:       "test-ca",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (ResourceCAPApplicationVersion)",
			res:            ResourceCAPApplicationVersion,
			expectedResult: true,
			itemName:       "test-cav",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (ResourceCertificate) valid owner",
			res:            ResourceCertificate,
			expectedResult: true,
			itemName:       "test-cert",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:            "Test enqueueModifiedResource (ResourceCertificate) invalid owner",
			res:             ResourceCertificate,
			expectedResult:  false,
			invalidOwnerRef: true,
			itemName:        "test-cert",
			itemNamespace:   corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (unknown resource)",
			res:            99,
			expectedResult: false,
			itemName:       "test-unknown-resource",
			itemNamespace:  corev1.NamespaceDefault,
		},
		{
			name:           "Test enqueueModifiedResource (invalid queue key)",
			res:            999,
			expectedResult: false,
			itemName:       "test-unknown-key",
			itemNamespace:  corev1.NamespaceDefault,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Deregister metrics
			defer deregisterMetrics()

			c := getTestController(testResources{})
			expectedResult = false

			queues := map[int]workqueue.TypedRateLimitingInterface[QueueItem]{
				ResourceCAPApplication:        &dummyType{},
				ResourceCAPApplicationVersion: &dummyType{},
				ResourceCAPTenant:             &dummyType{},
				ResourceCAPTenantOperation:    &dummyType{},
				// ResourceOperatorDomains:       &dummyType{},
			}

			testC := &Controller{
				kubeClient:                  c.kubeClient,
				crdClient:                   c.crdClient,
				istioClient:                 c.istioClient,
				gardenerCertificateClient:   c.gardenerCertificateClient,
				gardenerDNSClient:           c.gardenerDNSClient,
				kubeInformerFactory:         c.kubeInformerFactory,
				crdInformerFactory:          c.crdInformerFactory,
				istioInformerFactory:        c.istioInformerFactory,
				gardenerCertInformerFactory: c.gardenerCertInformerFactory,
				gardenerDNSInformerFactory:  c.gardenerDNSInformerFactory,
				queues:                      queues,
			}

			testC.initializeInformers()
			var res interface{}
			switch tt.res {
			case ResourceCAPApplication:
				res = createCaCRO(tt.itemName, false)
			case ResourceCAPApplicationVersion:
				ca := createCaCRO(tt.itemName, false)
				cav := createCavCRO(tt.itemName, v1alpha1.CAPApplicationVersionStateReady, defaultVersion)
				cav.ObjectMeta.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind))}
				res = cav
			case ResourceCertificate:
				// set label on a pod to simulate certificate in a different namespace
				cert := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tt.itemName, Annotations: map[string]string{
					AnnotationOwnerIdentifier: KindMap[ResourceCAPApplication] + "." + tt.itemNamespace + "." + tt.itemName,
				}, Labels: map[string]string{
					LabelOwnerIdentifierHash: sha1Sum(KindMap[ResourceCAPApplication], tt.itemNamespace, tt.itemName),
				}}}
				// Invalid label
				if tt.invalidOwnerRef {
					cert.Annotations[AnnotationOwnerIdentifier] = tt.itemNamespace + "." + tt.itemName
					cert.Labels[LabelOwnerIdentifierHash] = sha1Sum(tt.itemNamespace, tt.itemName)
				}
				res = cert
			case 999:
				res = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tt.itemName}}
			}
			// Add/delete
			testC.enqueueModifiedResource(tt.res, res, nil)
			if expectedResult != tt.expectedResult {
				t.Error("Unexpected result", expectedResult)
			}
			// Update
			testC.enqueueModifiedResource(tt.res, res, res)
			if expectedResult != tt.expectedResult {
				t.Error("Unexpected result", expectedResult)
			}
		})
	}
}
