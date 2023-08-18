/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	certManager "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certManagerInformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	gardenerCert "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	gardenerCertInformers "github.com/gardener/cert-management/pkg/client/cert/informers/externalversions"
	gardenerDNS "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned"
	gardenerDNSInformers "github.com/gardener/external-dns-management/pkg/client/dns/informers/externalversions"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	v1alpha1scheme "github.com/sap/cap-operator/pkg/client/clientset/versioned/scheme"
	crdInformers "github.com/sap/cap-operator/pkg/client/informers/externalversions"
	istio "istio.io/client-go/pkg/clientset/versioned"
	istioscheme "istio.io/client-go/pkg/clientset/versioned/scheme"
	istioInformers "istio.io/client-go/pkg/informers/externalversions"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type Controller struct {
	kubeClient                   kubernetes.Interface
	crdClient                    versioned.Interface
	istioClient                  istio.Interface
	gardenerCertificateClient    gardenerCert.Interface
	certManagerCertificateClient certManager.Interface
	gardenerDNSClient            gardenerDNS.Interface
	kubeInformerFactory          informers.SharedInformerFactory
	crdInformerFactory           crdInformers.SharedInformerFactory
	istioInformerFactory         istioInformers.SharedInformerFactory
	gardenerCertInformerFactory  gardenerCertInformers.SharedInformerFactory
	certManagerInformerFactory   certManagerInformers.SharedInformerFactory
	gardenerDNSInformerFactory   gardenerDNSInformers.SharedInformerFactory
	queues                       map[int]workqueue.RateLimitingInterface
	eventBroadcaster             events.EventBroadcaster
	eventRecorder                events.EventRecorder
}

func NewController(client kubernetes.Interface, crdClient versioned.Interface, istioClient istio.Interface, gardenerCertificateClient gardenerCert.Interface, certManagerCertificateClient certManager.Interface, gardenerDNSClient gardenerDNS.Interface) *Controller {
	queues := map[int]workqueue.RateLimitingInterface{
		ResourceCAPApplication:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ResourceCAPApplicationVersion: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ResourceCAPTenant:             workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ResourceCAPTenantOperation:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ResourceOperatorDomains:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	// Use 30mins as the default Resync interval for kube / proprietary  resources
	kubeInformerFactory := informers.NewSharedInformerFactory(client, 30*time.Minute)
	istioInformerFactory := istioInformers.NewSharedInformerFactory(istioClient, 30*time.Minute)

	var gardenerCertInformerFactory gardenerCertInformers.SharedInformerFactory
	var gardenerDNSInformerFactory gardenerDNSInformers.SharedInformerFactory
	var certManagerInformerFactory certManagerInformers.SharedInformerFactory
	switch certificateManager() {
	case certManagerGardener:
		gardenerCertInformerFactory = gardenerCertInformers.NewSharedInformerFactory(gardenerCertificateClient, 30*time.Minute)
	case certManagerCertManagerIO:
		certManagerInformerFactory = certManagerInformers.NewSharedInformerFactory(certManagerCertificateClient, 30*time.Minute)
	}
	switch dnsManager() {
	case dnsManagerGardener:
		gardenerDNSInformerFactory = gardenerDNSInformers.NewSharedInformerFactory(gardenerDNSClient, 30*time.Minute)
	case dnsManagerKubernetes:
		// no activity needed on our side so far
	}

	// Use 60 as the default Resync interval for our custom resources (CAP CROs)
	crdInformerFactory := crdInformers.NewSharedInformerFactory(crdClient, 60*time.Second)

	// initialize event recorder
	scheme := runtime.NewScheme()
	kubescheme.AddToScheme(scheme)
	v1alpha1scheme.AddToScheme(scheme)
	istioscheme.AddToScheme(scheme)
	eventBroadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: client.EventsV1()})
	eventBroadcaster.StartStructuredLogging(klog.Level(1))
	recorder := eventBroadcaster.NewRecorder(scheme, "cap-controller.sme.sap.com")

	c := &Controller{
		kubeClient:                   client,
		crdClient:                    crdClient,
		istioClient:                  istioClient,
		gardenerCertificateClient:    gardenerCertificateClient,
		certManagerCertificateClient: certManagerCertificateClient,
		gardenerDNSClient:            gardenerDNSClient,
		kubeInformerFactory:          kubeInformerFactory,
		crdInformerFactory:           crdInformerFactory,
		istioInformerFactory:         istioInformerFactory,
		gardenerCertInformerFactory:  gardenerCertInformerFactory,
		certManagerInformerFactory:   certManagerInformerFactory,
		gardenerDNSInformerFactory:   gardenerDNSInformerFactory,
		queues:                       queues,
		eventBroadcaster:             eventBroadcaster,
		eventRecorder:                recorder,
	}
	return c
}

func throwInformerStartError(resources map[reflect.Type]bool) {
	for resource, ok := range resources {
		if !ok {
			klog.Error("could not start informer for resource ", resource.String())
		}
	}
}

func (c *Controller) Start(ctx context.Context) {
	// ensure queue shutdown
	go func() {
		<-ctx.Done()
		for _, q := range c.queues {
			q.ShutDown()
		}
	}()

	c.initializeInformers()

	// start event recorder
	c.eventBroadcaster.StartRecordingToSink(ctx.Done())

	// start informers and wait for cache sync
	c.kubeInformerFactory.Start(ctx.Done())
	throwInformerStartError(c.kubeInformerFactory.WaitForCacheSync(ctx.Done()))

	c.crdInformerFactory.Start(ctx.Done())
	throwInformerStartError(c.crdInformerFactory.WaitForCacheSync(ctx.Done()))

	c.istioInformerFactory.Start(ctx.Done())
	throwInformerStartError(c.istioInformerFactory.WaitForCacheSync(ctx.Done()))

	switch certificateManager() {
	case certManagerGardener:
		c.gardenerCertInformerFactory.Start(ctx.Done())
		throwInformerStartError(c.gardenerCertInformerFactory.WaitForCacheSync(ctx.Done()))
	case certManagerCertManagerIO:
		c.certManagerInformerFactory.Start(ctx.Done())
		throwInformerStartError(c.certManagerInformerFactory.WaitForCacheSync(ctx.Done()))
	}

	switch dnsManager() {
	case dnsManagerGardener:
		c.gardenerDNSInformerFactory.Start(ctx.Done())
		throwInformerStartError(c.gardenerDNSInformerFactory.WaitForCacheSync(ctx.Done()))
	case dnsManagerKubernetes:
		// no activity needed on our side so far
	}

	// create context for worker queues
	qCxt, qCancel := context.WithCancel(ctx)
	defer qCancel()

	var wg sync.WaitGroup
	for k := range c.queues {
		wg.Add(1)
		go func(key int) {
			defer wg.Done()
			err := c.processQueue(qCxt, key)
			if err != nil {
				klog.Error("worker queue ", key, " ended with error: ", err.Error())
			}
			qCancel() // cancel context to inform other workers
		}(k)
	}

	// wait for workers
	wg.Wait()
}

func (c *Controller) processQueue(ctx context.Context, key int) error {
	klog.Info("starting to process queue ", getResourceKindFromKey(key))
	for {
		select {
		case <-ctx.Done():
			klog.Info("context done; ending processing of queue ", getResourceKindFromKey(key))
			return nil
		default: // fall through - to avoid blocking
			err := c.processQueueItem(ctx, key)
			if err != nil {
				return err
			}
		}
	}
}

func (c *Controller) processQueueItem(ctx context.Context, key int) error {
	q, ok := c.queues[key]
	if !ok {
		return fmt.Errorf("unknown queue; ending worker %d", key)
	}

	klog.V(2).Info("current work queue (", getResourceKindFromKey(key), ") length: ", q.Len())

	i, shutdown := q.Get()
	if shutdown {
		return fmt.Errorf("queue (%d) shutdown", key) // stop processing when the queue has been shutdown
	}

	// [IMPORTANT] always mark the item as done (after processing it)
	defer q.Done(i)

	var (
		err      error
		skipItem bool
		result   *ReconcileResult
	)
	item, ok := i.(QueueItem)
	if !ok {
		klog.Error("unknown item found in queue ", getResourceKindFromKey(key))
		return nil // process next item
	}

	attempts := q.NumRequeues(item)
	klog.Info("processing ", item.ResourceKey.Namespace, ".", item.ResourceKey.Name, " of type ", getResourceKindFromKey(key), " (attempt ", attempts, ")")

	switch item.Key {
	case ResourceCAPApplication:
		result, err = c.reconcileCAPApplication(ctx, item, attempts)
	case ResourceCAPApplicationVersion:
		result, err = c.reconcileCAPApplicationVersion(ctx, item, attempts)
	case ResourceCAPTenant:
		result, err = c.reconcileCAPTenant(ctx, item, attempts)
	case ResourceCAPTenantOperation:
		result, err = c.reconcileCAPTenantOperation(ctx, item, attempts)
	case ResourceOperatorDomains:
		err = c.reconcileOperatorDomains(ctx, item, attempts)
	default:
		err = errors.New("unidentified queue item")
		skipItem = true
	}
	// Handle reconcile errors
	if err != nil {
		klog.Error("queue processing error (", getResourceKindFromKey(key), "): ", err.Error())
		if !skipItem {
			// add back to queue for re-processing
			q.AddRateLimited(i)
			return nil
		}
	}

	// Forget the item after processing it
	// This just clears the rate limiter from tracking the item
	q.Forget(i)

	if result != nil {
		// requeue resources specified in the reconciliation result
		c.processReconcileResult(result)
	}

	return nil
}

func (c *Controller) processReconcileResult(result *ReconcileResult) {
	for i, items := range result.requeueResources {
		q, ok := c.queues[i]
		if !ok {
			klog.Errorf("could not identify a resource queue with key %v", i)
			return
		}
		for _, item := range items {
			klog.Infof("(re)queueing %s.%s as %s after %s", item.resourceKey.Namespace, item.resourceKey.Name, KindMap[i], item.requeueAfter.String())
			// add back item to queue w/o rate limits for re-processing after specified duration
			q.AddAfter(QueueItem{Key: i, ResourceKey: item.resourceKey}, item.requeueAfter)
		}
	}
}
