/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"maps"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	networkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	CAPDomainEventProcessingStarted         = "ProcessingStarted"
	CAPDomainEventMissingIngressGatewayInfo = "MissingIngressGatewayInfo"
)

func (c *Controller) reconcileDomain(ctx context.Context, item QueueItem, attempts int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPDomains().Lister()
	cached, err := lister.CAPDomains("").Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	dom := cached.DeepCopy()

	defer func() {
		if statusErr := c.updateCAPDomainStatus(ctx, dom); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	// (1) prepare (e.g. labels, finalizers)
	if update, err := c.prepareCAPDomain(ctx, dom); err != nil {
		return nil, err
	} else if update {
		return c.updateCAPDomain(ctx, dom, true)
	}

	// (2) handle deletion - TODO

	// (3) reconcile gateway and certificate
	domainInfo, err := c.getDomainInfo(ctx, dom)
	if err != nil {
		return
	}
	err = c.reconcileDomainGateway(ctx, dom, domainInfo)
	if err != nil {
		return
	}

	return
}

func (c *Controller) updateCAPDomainStatus(ctx context.Context, dom *v1alpha1.ClusterDomain) error {
	if isDeletionImminent(&dom.ObjectMeta) {
		return nil
	}

	if len(dom.Status.Conditions) == 0 {
		// initialize conditions - with processing status
		dom.SetStatusWithReadyCondition(dom.Status.State, metav1.ConditionFalse, "Processing", "")
	}
	domUpdated, err := c.crdClient.SmeV1alpha1().Domains(dom.Namespace).UpdateStatus(ctx, dom, metav1.UpdateOptions{})
	// update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	return err
}

func (c *Controller) prepareCAPDomain(ctx context.Context, dom *v1alpha1.ClusterDomain) (update bool, err error) {
	// Do nothing when object is deleted
	if dom.DeletionTimestamp != nil {
		return false, nil
	}

	// set domain identifier hash as a label
	domHash := sha1Sum(dom.Spec.Domain)
	if dom.Labels == nil {
		dom.Labels = map[string]string{}
	}
	if v, ok := dom.Labels[LabelDomainIdentifierHash]; !ok || v != domHash {
		list, err := c.crdClient.SmeV1alpha1().CAPDomains("").List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(map[string]string{LabelDomainIdentifierHash: domHash}).String()})
		if err != nil {
			return false, err
		}
		if len(list.Items) > 0 {
			dom.SetStatusWithReadyCondition(v1alpha1.DomainStateError, metav1.ConditionFalse, "DomainAlreadyExists", fmt.Sprintf("domain %s is already specified in another %s", dom.Spec.Domain, v1alpha1.CAPDomainKind))
			return false, err
		}
		dom.Labels[LabelDomainIdentifierHash] = domHash
		update = true
	}

	// set finalizers if not added
	if dom.Finalizers == nil {
		dom.Finalizers = []string{}
	}
	if addFinalizer(&dom.Finalizers, FinalizerCAPDomain) {
		update = true
	}

	return update, nil
}

func (c *Controller) updateCAPDomain(ctx context.Context, dom *v1alpha1.ClusterDomain, requeue bool) (result *ReconcileResult, err error) {
	var domUpdated *v1alpha1.ClusterDomain
	domUpdated, err = c.crdClient.SmeV1alpha1().CAPDomains("").Update(ctx, dom, metav1.UpdateOptions{})
	// Update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	if requeue {
		result = NewReconcileResultWithResource(ResourceCAPDomain, dom.Name, dom.Namespace, 0)
	}
	return
}

func (c *Controller) getDomainInfo(ctx context.Context, dom *v1alpha1.ClusterDomain) (info *ingressGatewayInfo, err error) {
	// create ingress gateway selector from labels
	selector, err := labels.ValidatedSelectorFromSet(dom.Spec.Selector)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			c.Event(dom, nil, corev1.EventTypeWarning, CAPDomainEventMissingIngressGatewayInfo, EventActionProcessingDomainResources, err.Error())
		}
	}()

	// Get relevant Ingress Gateway list
	list, err := c.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}

	// determine relevant ingress gateway namespace
	namespace := ""
	name := ""
	// Create a dummy lookup map for determining relevant pods
	relevantPodsNames := map[string]struct{}{}
	for _, pod := range list.Items {
		// We only support 1 ingress gateway pod namespace as of now! (Multiple pods e.g. replicas can exist in the same namespace)
		if namespace == "" {
			namespace = pod.Namespace
			name = pod.Name
		} else if namespace != pod.Namespace {
			return nil, fmt.Errorf("more than one matching ingress gateway pod namespaces found for %s %s", v1alpha1.CAPDomainKind, dom.Name)
		}
		relevantPodsNames[pod.Name] = struct{}{}
	}
	if namespace == "" {
		return nil, fmt.Errorf("no matching ingress gateway pod found for %s %s", v1alpha1.CAPDomainKind, dom.Name)
	}

	// Get DNS Target
	// First try to use dnsTarget --> if it is set
	dnsTarget := dom.Spec.DnsTarget
	// Attempt to get dnsTarget from Env
	if dnsTarget == "" {
		dnsTarget = envDNSTarget()
	}
	// Finally attempt to get dnsTarget from Service via annotation(s)
	if dnsTarget == "" {
		ingressGWSvc, err := c.getIngressGatewayService(ctx, namespace, relevantPodsNames, v1alpha1.CAPDomainKind, &dom.ObjectMeta)
		if err != nil {
			return nil, err
		}
		if ingressGWSvc != nil {
			dnsTarget = getDNSTarget(ingressGWSvc)
		}
	}
	// No DNS Target --> Error
	if dnsTarget == "" {
		return nil, fmt.Errorf("ingress gateway service not annotated with dns target name for %s %s", v1alpha1.CAPDomainKind, dom.Name)
	}

	// Return ingress Gateway info (Namespace and DNS target)
	return &ingressGatewayInfo{Namespace: namespace, Name: name, DNSTarget: dnsTarget}, nil
}

func (c *Controller) reconcileDomainGateway(ctx context.Context, dom *v1alpha1.ClusterDomain, domainInfo *ingressGatewayInfo) (err error) {
	list, err := c.istioClient.NetworkingV1().Gateways(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(dom.Name),
	}).String()})
	if len(list.Items) > 0 {

	}
	gw, err := c.istioClient.NetworkingV1().Gateways(domainInfo.Namespace).Get(ctx, fmt.Sprintf("%s-gw", dom.Name), metav1.GetOptions{})
	if err != nil {
		return
	}

	spec := networkingv1.Gateway{
		Selector: maps.Clone(dom.Spec.Selector),
		Servers: []*networkingv1.Server{
			{
				Hosts: []string{fmt.Sprintf("*.%s", dom.Spec.Domain)},
				Port: &networkingv1.Port{
					Number:   443,
					Protocol: "HTTPS",
					Name:     "https",
				},
				Tls: &networkingv1.ServerTLSSettings{
					CredentialName: dom.Name + "-tls",
					Mode:           dom.Spec.TlsMode,
				},
			},
		},
	}
	hash, err := serializeAndHash(&spec)
	if err != nil {
		return
	}

	if gw == nil { // create
		gw = &istionwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-", dom.Name),
				Namespace:    domainInfo.Namespace,
				Annotations: map[string]string{
					AnnotationResourceHash:    hash,
					AnnotationOwnerIdentifier: dom.Name,
				},
				Labels: map[string]string{
					LabelDomainIdentifierHash: sha1Sum(dom.Spec.Domain),
					LabelOwnerIdentifierHash:  sha1Sum(dom.Name),
				},
			},
			Spec: spec,
		}
		gw, err = c.istioClient.NetworkingV1().Gateways(domainInfo.Namespace).Create(ctx, gw, metav1.CreateOptions{})
	} else if gw.Annotations[AnnotationResourceHash] != hash { // update
		gw = gw.DeepCopy()
		gw.Spec = spec
		// Update hash value on annotation
		updateResourceAnnotation(&gw.ObjectMeta, hash)
		// Trigger the actual update on the resource
		gw, err = c.istioClient.NetworkingV1().Gateways(domainInfo.Namespace).Update(ctx, gw, metav1.UpdateOptions{})
	}

	return
}

// func (c *Controller) handleDomainCertificate(ctx context.Context, dom *v1alpha1.CAPDomain, domainInfo *ingressGatewayInfo) error {
// 	switch certificateManager() {
// 	case certManagerGardener:
// 	case certManagerCertManagerIO:
// 	}

// 	hash := sha256Sum(fmt.Sprintf("%v", relevantDomainInfo))
// 	dnsTarget := trimDNSTarget(relevantDomainInfo.dnsTarget)
// 	switch certificateManager() {
// 	case certManagerGardener:
// 		cert, err := c.getGardenerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
// 		if err != nil {
// 			return err
// 		}
// 		// If no certiicate exists yet --> create one
// 		if cert == nil {
// 			cert := &certv1alpha1.Certificate{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Name: certName,
// 					Annotations: map[string]string{
// 						AnnotationResourceHash:    hash,
// 						AnnotationOwnerIdentifier: OperatorDomainLabel,
// 					},
// 					Labels: map[string]string{
// 						LabelRelevantDNSTarget:   dnsTargetSum,
// 						LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
// 					},
// 				},
// 				Spec: getGardenerCertificateSpec(dnsTarget, dnsTarget),
// 			}
// 			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
// 			_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(relevantDomainInfo.Namespace).Create(ctx, cert, metav1.CreateOptions{})
// 		} else if cert.Annotations[AnnotationResourceHash] != hash {
// 			// Update the relevant certificate parts, if there are changes (detected via sha256 sum)
// 			cert = cert.DeepCopy()
// 			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
// 			// Update hash value on annotation
// 			updateResourceAnnotation(&cert.ObjectMeta, hash)
// 			// Trigger the actual update on the resource
// 			_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(relevantDomainInfo.Namespace).Update(ctx, cert, metav1.UpdateOptions{})
// 		}
// 		return err
// 	case certManagerCertManagerIO:
// 		cert, err := c.getCertManagerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
// 		if err != nil {
// 			return err
// 		}
// 		// If no certiicate exists yet --> create one
// 		if cert == nil {
// 			cert := &certManagerv1.Certificate{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Name: certName,
// 					Annotations: map[string]string{
// 						AnnotationResourceHash:    hash,
// 						AnnotationOwnerIdentifier: OperatorDomainLabel,
// 					},
// 					Labels: map[string]string{
// 						LabelRelevantDNSTarget:   dnsTargetSum,
// 						LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
// 					},
// 				},
// 				Spec: getCertManagerCertificateSpec("*."+dnsTarget, dnsTarget),
// 			}
// 			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
// 			_, err = c.certManagerCertificateClient.CertmanagerV1().Certificates(relevantDomainInfo.Namespace).Create(ctx, cert, metav1.CreateOptions{})
// 		} else if cert.Annotations[AnnotationResourceHash] != hash {
// 			// Update the relevant certificate parts, if there are changes (detected via sha256 sum)
// 			cert = cert.DeepCopy()
// 			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
// 			// Update hash value on annotation
// 			updateResourceAnnotation(&cert.ObjectMeta, hash)
// 			// Trigger the actual update on the resource
// 			_, err = c.certManagerCertificateClient.CertmanagerV1().Certificates(relevantDomainInfo.Namespace).Update(ctx, cert, metav1.UpdateOptions{})
// 		}
// 		return err
// 	}
// 	return nil
// }
