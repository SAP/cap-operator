/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
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
	ResourceCAPApplication = iota
	ResourceCAPApplicationVersion
	ResourceCAPTenant
	ResourceCAPTenantOperation
	ResourceDomain
	ResourceClusterDomain
	ResourceSecret
	ResourceJob
	ResourceGateway
	ResourceCertificate
	ResourceDNSEntry
	ResourceVirtualService
	ResourceDestinationRule
)

const queuing = "queuing resource for reconciliation"

const defaultDependantDelay = 3 * time.Second

var (
	KindMap = map[int]string{
		ResourceCAPApplication:        v1alpha1.CAPApplicationKind,
		ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind,
		ResourceCAPTenant:             v1alpha1.CAPTenantKind,
		ResourceCAPTenantOperation:    v1alpha1.CAPTenantOperationKind,
		ResourceDomain:                v1alpha1.DomainKind,
		ResourceClusterDomain:         v1alpha1.ClusterDomainKind,
	}
)

type NamespacedResourceKey struct {
	Namespace string
	Name      string
}

var QueueMapping map[int]map[int]string = map[int]map[int]string{
	ResourceCAPApplication:        {ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceCAPApplicationVersion: {ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind, ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceCAPTenant:             {ResourceCAPTenant: v1alpha1.CAPTenantKind, ResourceCAPApplication: v1alpha1.CAPApplicationKind},
	ResourceCAPTenantOperation:    {ResourceCAPTenantOperation: v1alpha1.CAPTenantOperationKind, ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceDomain:                {ResourceDomain: v1alpha1.DomainKind},
	ResourceClusterDomain:         {ResourceClusterDomain: v1alpha1.ClusterDomainKind},
	ResourceJob:                   {ResourceCAPTenantOperation: v1alpha1.CAPTenantOperationKind, ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind},
	ResourceGateway:               {ResourceDomain: v1alpha1.DomainKind, ResourceClusterDomain: v1alpha1.ClusterDomainKind},
	ResourceCertificate:           {ResourceDomain: v1alpha1.DomainKind, ResourceClusterDomain: v1alpha1.ClusterDomainKind},
	ResourceDNSEntry:              {ResourceDomain: v1alpha1.DomainKind, ResourceClusterDomain: v1alpha1.ClusterDomainKind},
	ResourceVirtualService:        {ResourceCAPTenant: v1alpha1.CAPTenantKind},
	ResourceDestinationRule:       {ResourceCAPApplicationVersion: v1alpha1.CAPApplicationVersionKind},
}

type QueueItem struct {
	Key         int
	ResourceKey NamespacedResourceKey
}

func (c *Controller) initializeInformers() {
	c.registerCAPApplicationListeners()
	c.registerCAPApplicationVersionListeners()
	c.registerCAPTenantListeners()
	c.registerCAPTenantOperationListeners()
	c.registerDomainListeners()
	c.registerClusterDomainListeners()
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
	klog.InfoS("informers initialized")
}

func (c *Controller) getEventHandlerFuncsForResource(res int) cache.ResourceEventHandlerFuncs {
	_, ok := QueueMapping[res]
	if !ok {
		return cache.ResourceEventHandlerFuncs{}
	}
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			c.enqueueModifiedResource(res, new, nil)
		},
		UpdateFunc: func(old, new any) {
			c.enqueueModifiedResource(res, new, old)
		},
		DeleteFunc: func(old any) {
			c.enqueueModifiedResource(res, nil, old)
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

func (c *Controller) registerClusterDomainListeners() {
	c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceClusterDomain))
}

func (c *Controller) registerDomainListeners() {
	c.crdInformerFactory.Sme().V1alpha1().Domains().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceDomain))
}

func (c *Controller) registerJobListeners() {
	c.kubeInformerFactory.Batch().V1().Jobs().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceJob))
}

func (c *Controller) registerVirtualServiceListeners() {
	c.istioInformerFactory.Networking().V1().VirtualServices().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceVirtualService))
}

func (c *Controller) registerDestinationRuleListeners() {
	c.istioInformerFactory.Networking().V1().DestinationRules().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceDestinationRule))
}

func (c *Controller) registerSecretListeners() {
	c.kubeInformerFactory.Core().V1().Secrets().Informer().
		AddEventHandler(c.getEventHandlerFuncsForResource(ResourceSecret))
}

func (c *Controller) registerGatewayListeners() {
	c.istioInformerFactory.Networking().V1().Gateways().Informer().
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

func (c *Controller) enqueueModifiedResource(sourceKey int, new, old any) {
	newObj, newOk := getMetaObject(new)
	oldObj, oldOk := getMetaObject(old)
	if newOk && oldOk && oldObj.GetResourceVersion() == newObj.GetResourceVersion() {
		klog.V(2).InfoS("skipping update scenario", "key", sourceKey, "new", newObj.GetName(), "sourceKey", sourceKey)
		return // no changes in update
	}

	mapping, ok := QueueMapping[sourceKey]
	if !ok {
		klog.ErrorS(nil, "could not map modification event to a work queue", "key", sourceKey)
		return
	}

	for dependentKey, dependentKind := range mapping {
		q := c.queues[dependentKey]
		item := determineQueueItem(dependentKey, sourceKey, oldObj, newObj, dependentKind)
		if item == nil {
			continue
		}
		// Change on the main resource
		if dependentKey == sourceKey {
			q.Add(*item)
		} else {
			q.AddAfter(*item, defaultDependantDelay)
		}
	}
}

func determineQueueItem(dependentKey int, sourceKey int, oldObj metav1.Object, newObj metav1.Object, dependentKind string) *QueueItem {
	if dependentKey == sourceKey {
		// Skip queue of CRO itelf on delete
		// When the change (Update) is directly on the CRO check for spec and annotation changes - omits status changes
		if newObj == nil || (oldObj != nil && !hasReconciliationRelevantChanges(newObj, oldObj)) {
			return nil // do not enqueue
		}
		klog.InfoS(queuing, "namespace", newObj.GetNamespace(), "name", newObj.GetName(), "kind", dependentKind)
		return &QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: newObj.GetName(), Namespace: newObj.GetNamespace()}}
	}
	// Skip Queue of Owner on create --> the owner would have created these anyway
	if oldObj == nil {
		return nil
	}
	// Get the relevant obj to find the owner (usually newObj)
	obj := newObj
	// In case of delete newObj doesn't exist, hence use the oldObj to determine owner
	if newObj == nil {
		obj = oldObj
	}
	if owner, ok := getOwnerByKind(obj.GetOwnerReferences(), dependentKind); ok {
		klog.InfoS(queuing, "namespace", obj.GetNamespace(), "name", owner.Name, "kind", dependentKind)
		return &QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: owner.Name, Namespace: obj.GetNamespace()}}
	} else if owner, ok := getOwnerFromObjectMetadata(obj, dependentKind); ok {
		klog.InfoS(queuing, "namespace", owner.Namespace, "name", owner.Name, "kind", dependentKind)
		return &QueueItem{Key: dependentKey, ResourceKey: NamespacedResourceKey{Name: owner.Name, Namespace: owner.Namespace}}
	}
	klog.V(2).InfoS("skipping --> owner not found", "namespace", obj.GetNamespace(), "name", obj.GetName(), "kind", dependentKind, "sourceKey", sourceKey)
	return nil
}

func getMetaObject(obj any) (metav1.Object, bool) {
	if obj == nil {
		return nil, false
	}

	ok := true
	metaObj, err := meta.Accessor(obj)
	if err != nil {
		klog.ErrorS(err, "could not type cast event object to meta object: ")
		ok = false
	}
	return metaObj, ok
}

func hasReconciliationRelevantChanges(newObj, oldObj metav1.Object) bool {
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
