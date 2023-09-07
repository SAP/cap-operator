/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"reflect"
	"time"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	ResourceCAPTenant = iota
	ResourceCAPApplicationVersion
	ResourceCAPApplication
	ResourceCAPTenantOperation
	ResourceJob
	ResourceSecret
	ResourceGateway
	ResourceCertificate
	ResourceDNSEntry
	ResourceOperatorDomains
	ResourceVirtualService
	ResourceDestinationRule
)

const (
	OperatorDomains = "OperatorDomains"
)

const queuing = "queuing "

var (
	KindMap = map[int]string{
		ResourceCAPTenant:             v1alpha1.CAPTenantKind,
		ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind,
		ResourceCAPApplication:        v1alpha1.CAPApplicationKind,
		ResourceCAPTenantOperation:    v1alpha1.CAPTenantOperationKind,
		ResourceOperatorDomains:       OperatorDomains,
	}
)

type NamespacedResourceKey struct {
	Namespace string
	Name      string
}

var QueueMapping map[int]map[int]string = map[int]map[int]string{
	ResourceCAPTenantOperation:    {ResourceCAPTenantOperation: v1alpha1.CAPTenantOperationKind, ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceJob:                   {ResourceCAPTenantOperation: v1alpha1.CAPTenantOperationKind, ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind},
	ResourceSecret:                {ResourceCAPApplication: v1alpha1.CAPApplicationKind, ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind},
	ResourceGateway:               {ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceCertificate:           {ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceDNSEntry:              {ResourceCAPApplication: v1alpha1.CAPApplicationKind, ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceCAPTenant:             {ResourceCAPTenant: v1alpha1.CAPTenantKind, ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceVirtualService:        {ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceDestinationRule:       {ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceCAPApplicationVersion: {ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind, ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceCAPApplication:        {ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceOperatorDomains:       {ResourceOperatorDomains: OperatorDomains},
}

type QueueItem struct {
	Key         int
	ResourceKey NamespacedResourceKey
}

func (c *Controller) initializeInformers() {
	c.registerCAPTenantListeners()
	c.registerCAPApplicationListeners()
	c.registerCAPApplicationVersionListeners()
	c.registerCAPTenantOperationListeners()
	c.registerJobListeners()
	c.registerSecretListeners()
	c.registerGatewayListeners()
	c.registerVirtualServiceListeners()
	c.registerDestinationRuleListeners()
	switch certificateManager() {
	case certManagerGardener:
		c.registerGardenerCertificateListeners()
	case certManagerCertManagerIO:
		c.registerCertManagerCertificateListeners()
	}
	switch dnsManager() {
	case dnsManagerGardener:
		c.registerGardenerDNSEntrytListeners()
	case dnsManagerKubernetes:
		// no activity needed on our side so far
	}
	klog.Info("informers initialized")
}

func (c *Controller) getEventHandlerFuncsForResource(res int) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(new interface{}) {
			c.enqueueModifiedResource(res, new, nil)
		},
		UpdateFunc: func(old, new interface{}) {
			c.enqueueModifiedResource(res, new, old)
		},
		DeleteFunc: func(old interface{}) {
			c.enqueueModifiedResource(res, old, nil)
		},
	}
}

func (c *Controller) registerCAPApplicationListeners() {
	c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCAPApplication))
}

func (c *Controller) registerCAPApplicationVersionListeners() {
	c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCAPApplicationVersion))
}

func (c *Controller) registerCAPTenantListeners() {
	c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCAPTenant))
}

func (c *Controller) registerCAPTenantOperationListeners() {
	c.crdInformerFactory.Sme().V1alpha1().CAPTenantOperations().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCAPTenantOperation))
}

func (c *Controller) registerJobListeners() {
	c.kubeInformerFactory.Batch().V1().Jobs().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceJob))
}

func (c *Controller) registerVirtualServiceListeners() {
	c.istioInformerFactory.Networking().V1beta1().VirtualServices().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceVirtualService))
}

func (c *Controller) registerDestinationRuleListeners() {
	c.istioInformerFactory.Networking().V1beta1().DestinationRules().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceDestinationRule))
}

func (c *Controller) registerSecretListeners() {
	c.kubeInformerFactory.Core().V1().Secrets().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceSecret))
}

func (c *Controller) registerGatewayListeners() {
	c.istioInformerFactory.Networking().V1beta1().Gateways().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceGateway))
}

func (c *Controller) registerGardenerCertificateListeners() {
	c.gardenerCertInformerFactory.Cert().V1alpha1().Certificates().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCertificate))
}

func (c *Controller) registerCertManagerCertificateListeners() {
	c.certManagerInformerFactory.Certmanager().V1().Certificates().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceCertificate))
}

func (c *Controller) registerGardenerDNSEntrytListeners() {
	c.gardenerDNSInformerFactory.Dns().V1alpha1().DNSEntries().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceDNSEntry))
}

func (c *Controller) enqueueModifiedResource(sourceKey int, new, old interface{}) {
	newObj, ok := getMetaObject(new)
	if !ok {
		return
	}

	oldObj, ok := getMetaObject(old)
	if ok && oldObj.GetResourceVersion() == newObj.GetResourceVersion() {
		return // no changes in update
	}

	mapping, ok := QueueMapping[sourceKey]
	if !ok {
		klog.Error("could not map modification event to a work queue for key: ", sourceKey)
		return
	}

	for dependentKey, dependentKind := range mapping {
		q := c.queues[dependentKey]

		if dependentKey == sourceKey {
			// when the change is directly on the CRO check for spec and annotation changes - omits status changes
			if oldObj != nil && !hasReconciliationRelevantChanges(newObj, oldObj) {
				continue // do not enqueue
			}
			klog.Info(queuing, newObj.GetNamespace(), ".", newObj.GetName(), " as ", dependentKind)
			q.Add(QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: newObj.GetName(), Namespace: newObj.GetNamespace()}})
		} else if owner, ok := getOwnerByKind(newObj.GetOwnerReferences(), dependentKind); ok {
			klog.Info(queuing, newObj.GetNamespace(), ".", owner.Name, " as ", dependentKind)
			q.Add(QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: owner.Name, Namespace: newObj.GetNamespace()}})
		} else if owner, ok := getOwnerFromObjectMetadata(newObj, dependentKind); ok {
			klog.Info(queuing, owner.Namespace, ".", owner.Name, " as ", dependentKind)
			q.Add(QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: owner.Name, Namespace: owner.Namespace}})
		}
	}

	// Reconcile OperatorDomains just after all CAPApplication updates
	if sourceKey == ResourceCAPApplication {
		klog.Info(queuing, "all.domains", " as ", KindMap[ResourceOperatorDomains])
		// Reconcile Secondary domains via a dummy resource (separate reconciliation) after 1s
		c.queues[ResourceOperatorDomains].AddAfter(QueueItem{Key: ResourceOperatorDomains, ResourceKey: NamespacedResourceKey{Namespace: metav1.NamespaceAll, Name: ""}}, 1*time.Second)
	}
}

func getMetaObject(obj interface{}) (metav1.Object, bool) {
	if obj == nil {
		return nil, false
	}

	ok := true
	metaObj, err := meta.Accessor(obj)
	if err != nil {
		klog.Error("could not type cast event object to meta object: ", err.Error())
		ok = false
	}
	return metaObj, ok
}

func hasReconciliationRelevantChanges(newObj metav1.Object, oldObj metav1.Object) bool {
	if oldObj.GetGeneration() != newObj.GetGeneration() {
		// generation change denotes a change in the object spec
		return true
	}

	// annotation changes
	if !reflect.DeepEqual(oldObj.GetAnnotations(), newObj.GetAnnotations()) {
		return true
	}

	// changes in owner reference
	return !reflect.DeepEqual(oldObj.GetOwnerReferences(), newObj.GetOwnerReferences())
}
