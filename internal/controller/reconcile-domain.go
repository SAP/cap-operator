/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/sync/errgroup"
	networkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8snwv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	DomainEventMissingIngressGatewayInfo = "MissingIngressGatewayInfo"
	DomainEventCertificateNotReady       = "CertificateNotReady"
	DomainEventDNSEntriesNotReady        = "DNSEntriesNotReady"
	DomainEventDuplicateDomainHost       = "DuplicateDomainHost"
	EventActionProcessingDomainResources = "ProcessingDomainResources"
	LabelKubernetesServiceName           = "kubernetes.io/service-name"
	LabelKubernetesMetadataName          = "kubernetes.io/metadata.name"
)

func (c *Controller) reconcileDomain(ctx context.Context, item QueueItem, _ int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().Domains().Lister()
	cached, err := lister.Domains(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	dom := cached.DeepCopy()

	// prepare finalizers
	if prepareDomainEntity(dom) {
		if err = c.updateDomain(ctx, dom); err == nil {
			result = NewReconcileResultWithResource(ResourceDomain, dom.Name, dom.Namespace, 0)
		}
		return
	}

	defer func() {
		if statusErr := c.updateDomainStatus(ctx, dom); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	return reconcileDomainEntity(ctx, c, dom, dom.Namespace)
}

func (c *Controller) reconcileClusterDomain(ctx context.Context, item QueueItem, _ int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister()
	cached, err := lister.ClusterDomains(corev1.NamespaceAll).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	dom := cached.DeepCopy()

	// prepare finalizers
	if prepareDomainEntity(dom) {
		if err = c.updateClusterDomain(ctx, dom); err == nil {
			result = NewReconcileResultWithResource(ResourceClusterDomain, dom.Name, corev1.NamespaceAll, 0)
		}
		return
	}

	defer func() {
		if statusErr := c.updateClusterDomainStatus(ctx, dom); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	return reconcileDomainEntity(ctx, c, dom, util.GetNamespace())
}

func (c *Controller) updateDomain(ctx context.Context, dom *v1alpha1.Domain) error {
	domUpdated, err := c.crdClient.SmeV1alpha1().Domains(dom.Namespace).Update(ctx, dom, metav1.UpdateOptions{})
	// Update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	return err
}

func (c *Controller) updateDomainStatus(ctx context.Context, dom *v1alpha1.Domain) error {
	if isDeletionImminent(&dom.ObjectMeta) {
		return nil
	}
	domUpdated, err := c.crdClient.SmeV1alpha1().Domains(dom.Namespace).UpdateStatus(ctx, dom, metav1.UpdateOptions{})
	// update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	return err
}

func (c *Controller) updateClusterDomain(ctx context.Context, dom *v1alpha1.ClusterDomain) error {
	domUpdated, err := c.crdClient.SmeV1alpha1().ClusterDomains(corev1.NamespaceAll).Update(ctx, dom, metav1.UpdateOptions{})
	// Update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	return err
}

func (c *Controller) updateClusterDomainStatus(ctx context.Context, dom *v1alpha1.ClusterDomain) error {
	if isDeletionImminent(&dom.ObjectMeta) {
		return nil
	}
	domUpdated, err := c.crdClient.SmeV1alpha1().ClusterDomains(corev1.NamespaceAll).UpdateStatus(ctx, dom, metav1.UpdateOptions{})
	// update reference to the resource
	if domUpdated != nil {
		*dom = *domUpdated
	}
	return err
}

func reconcileDomainEntity[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, subResourceNamespace string) (result *ReconcileResult, err error) {
	// Check if the domain resource is being deleted
	if dom.GetMetadata().DeletionTimestamp != nil {
		return handleDomainResourceDeletion(ctx, c, dom)
	}

	if dom.GetStatus().State != v1alpha1.DomainStateProcessing {
		// set processing status
		dom.SetStatusWithReadyCondition(v1alpha1.DomainStateProcessing, metav1.ConditionFalse, "Processing", "Processing domain resources")
		return NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 0), nil
	}

	defer func() {
		if err != nil {
			dom.SetStatusWithReadyCondition(v1alpha1.DomainStateError, metav1.ConditionFalse, "ProcessingError", err.Error())
		}
	}()

	// process the domain realted resources
	if result, err = processDomainEntity(ctx, c, dom, subResourceNamespace); err != nil || result != nil {
		return
	}

	if result, err = checkDomainResourcesReady(ctx, dom, c); err != nil || result != nil {
		return
	}

	// Resource is ready, so we can set the status to ready
	dom.SetStatusWithReadyCondition(v1alpha1.DomainStateReady, metav1.ConditionTrue, "Ready", "Domain resources are ready")
	return

}

func checkDomainResourcesReady[T v1alpha1.DomainEntity](ctx context.Context, dom T, c *Controller) (result *ReconcileResult, err error) {
	var message string
	var resource string
	ready := false
	ownerId := formOwnerIdFromDomain(dom)

	defer func() {
		if err == nil && ready {

			return
		}
		if err == nil {
			message = "Waiting for " + resource + " to be ready"
			result = NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 3*time.Second)
		} else {
			message = err.Error()
		}
		c.Event(runtime.Object(dom), nil, corev1.EventTypeWarning, DomainEventCertificateNotReady, EventActionProcessingDomainResources, message)
	}()

	// wait for certificate to be ready
	if ready, err = areCertificatesReady(ctx, c, ownerId); err != nil || !ready {
		resource = "certificate"
		return
	}

	// wait for dns entries to be ready
	if ready, err = areDnsEntriesReady(ctx, c, ownerId); err != nil || !ready {
		resource = "dns entries"
		return
	}
	return
}

func processDomainEntity[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, subResourceNamespace string) (result *ReconcileResult, err error) {
	// check for duplicate domains
	if result, err = handleDuplicateDomainHosts(c, dom); err != nil || result != nil {
		return
	}

	ownerId := formOwnerIdFromDomain(dom)

	// We generate a unique name for other resources using the domain resource name
	subResourceName := strings.ReplaceAll(dom.GetName(), ".", "--")
	if len(subResourceName) > 57 {
		subResourceName = subResourceName[:57] // Istio Gateway name limit is 63 characters, but we need to reserve space for the generated name prefix
	}

	// get ingress information
	var (
		ingressInfo *ingressGatewayInfo
	)
	ingressInfo, err = getIngressInfo(ctx, c, dom)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingress information for %s: %w", ownerId, err)
	}
	dom.GetStatus().DnsTarget = sanitizeDNSTarget(ingressInfo.DNSTarget)

	// reconcile certificate
	credentialName, err := handleDomainCertificate(ctx, c, dom, ingressInfo.Namespace, subResourceName, subResourceNamespace, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain certificate for %s: %w", ownerId, err)
	}

	// handle additional ca certificate(s)
	if err := handleAdditionalCACertificate(ctx, c, dom, credentialName, ingressInfo.Namespace, ownerId); err != nil {
		return nil, fmt.Errorf("failed to reconcile additional ca certificate secret for %s: %w", ownerId, err)
	}

	// reconcile gateway
	err = handleDomainGateway(ctx, c, dom, credentialName, subResourceName, subResourceNamespace, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain gateway for %s: %w", ownerId, err)
	}

	// notify applications in case of domain changes
	if dom.GetSpec().Domain != dom.GetStatus().ObservedDomain {
		return notifyReferencingApplications(c, dom, result)
	}

	// handle network policy from the ingress gateway to the workload
	if err = handleDomainNetworkPolicies(ctx, c, dom, ownerId, subResourceName); err != nil {
		return nil, fmt.Errorf("failed to reconcile domain network policies for %s: %w", ownerId, err)
	}

	// handle dns entries
	err = handleDnsEntries(ctx, c, dom, ownerId, subResourceName, subResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain dns entries for %s: %w", ownerId, err)
	}

	return
}

func handleDuplicateDomainHosts[T v1alpha1.DomainEntity](c *Controller, dom T) (requeue *ReconcileResult, err error) {
	grp := errgroup.Group{}
	var (
		doms  []*v1alpha1.Domain
		cdoms []*v1alpha1.ClusterDomain
	)
	selector := labels.SelectorFromSet(labels.Set{
		LabelDomainHostHash: sha1Sum(dom.GetSpec().Domain),
	})
	grp.Go(func() (err error) {
		doms, err = c.crdInformerFactory.Sme().V1alpha1().Domains().Lister().List(selector)
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to list domains: %w", err)
		}
		return nil
	})
	grp.Go(func() (err error) {
		cdoms, err = c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister().List(selector)
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to list cluster domains: %w", err)
		}
		return nil
	})
	if err = grp.Wait(); err != nil {
		return
	}
	if len(doms)+len(cdoms) > 1 {
		// there are other domains with the same host
		// (1) set current domain to error state
		msg := "Identical domain host is specified in another Domain/ClusterDomain resource"
		dom.SetStatusWithReadyCondition(v1alpha1.DomainStateError, metav1.ConditionFalse, "DuplicateDomainHost", msg)
		c.Event(runtime.Object(dom), nil, corev1.EventTypeWarning, DomainEventDuplicateDomainHost, EventActionProcessingDomainResources, msg)

		// (2) requeue the other domain for setting error state and wait to retry reconciling the current domain resource
		requeue = NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 30*time.Second)
		addDuplicateDomainResourcesToQueue(dom, doms, requeue)
		addDuplicateDomainResourcesToQueue(dom, cdoms, requeue)
		return notifyReferencingApplications(c, dom, requeue)
	}
	return
}

func addDuplicateDomainResourcesToQueue[T v1alpha1.DomainEntity, E v1alpha1.DomainEntity](dom T, s []E, requeue *ReconcileResult) {
	for i := range s {
		if dom.GetKind() != s[i].GetKind() || dom.GetNamespace() != s[i].GetNamespace() || dom.GetName() != s[i].GetName() {
			if s[i].GetStatus().State == v1alpha1.DomainStateReady {
				requeue.AddResource(getResourceKeyFromKind(s[i]), s[i].GetName(), s[i].GetNamespace(), 0)
			}
		}
	}
}

func notifyReferencingApplications[T v1alpha1.DomainEntity](c *Controller, dom T, requeue *ReconcileResult) (*ReconcileResult, error) {
	cas, err := getReferencingApplications(c, dom)
	if err != nil {
		return nil, err
	}

	// set the observed domain in the status - do this only when the above step does not return an error
	defer func() {
		dom.SetStatusObservedDomain(dom.GetSpec().Domain)
	}()

	if requeue == nil {
		// requeue the domain only when the reconciliation result is nil
		requeue = NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 0)
	}

	if len(cas) == 0 {
		// no applications are referencing this domain
		return requeue, nil
	}

	for _, ca := range cas {
		requeue.AddResource(ResourceCAPApplication, ca.Name, ca.Namespace, 0)
	}

	return requeue, nil
}

func prepareDomainEntity[T v1alpha1.DomainEntity](dom T) (update bool) {
	// Do nothing when object is deleted
	if dom.GetMetadata().DeletionTimestamp != nil {
		return false
	}
	// add Finalizer to prevent direct deletion
	mo := dom.GetMetadata()
	if mo.Finalizers == nil {
		mo.Finalizers = []string{}
	}
	if addFinalizer(&mo.Finalizers, FinalizerDomain) {
		update = true
	}

	// add or update domain host hash label
	hash := sha1Sum(dom.GetSpec().Domain)
	if mo.Labels == nil {
		mo.Labels = map[string]string{
			LabelDomainHostHash: hash,
		}
		update = true
	} else if v, ok := mo.Labels[LabelDomainHostHash]; !ok || v != hash {
		mo.Labels[LabelDomainHostHash] = hash
		update = true
	}

	return update
}

func handleDomainGateway[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, credentialName, name, namespace, ownerId string) (err error) {
	// create a gateway selector from specified labels
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})
	gatewayList, err := c.istioClient.NetworkingV1().Gateways(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	found := !errors.IsNotFound(err)
	if err != nil && found {
		return fmt.Errorf("failed to get gateway for %s: %w", ownerId, err)
	}
	var gateway *istionwv1.Gateway
	if len(gatewayList.Items) == 1 {
		gateway = gatewayList.Items[0]
	} else {
		if len(gatewayList.Items) > 1 {
			return fmt.Errorf("found multiple gateways for %s, expected only one", ownerId)
		}
		// no gateway found, we will create a new one
		found = false

	}

	hostPrefix := "*/*."
	if dom.GetKind() == v1alpha1.DomainKind {
		hostPrefix = "./*."
	}
	gatewaySpec := &networkingv1.Gateway{
		Selector: dom.GetSpec().IngressSelector,
		Servers: []*networkingv1.Server{
			{
				Hosts: []string{hostPrefix + dom.GetSpec().Domain},
				Port: &networkingv1.Port{
					Number:   443,
					Name:     "https",
					Protocol: "HTTPS",
				},
				Tls: &networkingv1.ServerTLSSettings{
					Mode:           convertTlsMode(dom.GetSpec().TLSMode),
					CredentialName: credentialName,
				},
			},
		},
	}
	hash, err := serializeAndHash(gatewaySpec)
	if err != nil {
		return fmt.Errorf("failed to serialize gateway spec: %w", err)
	}

	if !found { // create
		gateway, err = c.istioClient.NetworkingV1().Gateways(namespace).Create(ctx, &istionwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: name + "-",
				Namespace:    namespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash: sha1Sum(ownerId),
					LabelOwnerGeneration:     fmt.Sprintf("%d", dom.GetMetadata().Generation),
				},
				Annotations: map[string]string{
					AnnotationResourceHash:    hash,
					AnnotationOwnerIdentifier: ownerId,
				},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(metav1.Object(dom), v1alpha1.SchemeGroupVersion.WithKind(dom.GetKind())),
				},
			},
			Spec: *gatewaySpec.DeepCopy(),
		}, metav1.CreateOptions{})
	} else if gateway.Annotations[AnnotationResourceHash] != hash { // update
		updateResourceAnnotation(&gateway.ObjectMeta, hash)
		gateway.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
		gateway.Spec = *gatewaySpec.DeepCopy()
		gateway, err = c.istioClient.NetworkingV1().Gateways(namespace).Update(ctx, gateway, metav1.UpdateOptions{})
	}
	// update the gateway in domain entity status as this is needed for VirtualService creation
	if err == nil && gateway != nil {
		dom.GetStatus().GatewayName = gateway.Name
	}

	return
}

func handleDomainCertificate[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, credentialNamespace, name, namespace, ownerId string) (credentialName string, err error) {
	h := CreateCertificateManager(c)
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})
	certs, err := h.ListCertificates(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		return "", fmt.Errorf("failed to list certificates for %s: %w", ownerId, err)
	}

	credentialName = h.GetCredentialName(namespace, name)

	info := &ManagedCertificateInfo{
		Domain:              dom.GetSpec().Domain,
		Name:                name,
		Namespace:           namespace,
		CredentialName:      credentialName,
		CredentialNamespace: credentialNamespace,
		OwnerId:             ownerId,
		OwnerGeneration:     dom.GetMetadata().Generation,
	}
	hash := info.Hash()

	certsForDeletion := []ManagedCertificate{}
	var (
		selectedCert ManagedCertificate
		consistent   bool
	)
	for i := range certs {
		cert := certs[i]
		if h.managerType == certManagerCertManagerIO && (cert.GetNamespace() != credentialNamespace || consistent) {
			certsForDeletion = append(certsForDeletion, cert)
			continue
		}
		if cert.GetAnnotations()[AnnotationResourceHash] == hash {
			// this certificate is already up to date
			if selectedCert != nil {
				certsForDeletion = append(certsForDeletion, selectedCert)
			}
			selectedCert = cert
			consistent = true
			continue
		}
		if selectedCert == nil {
			// this is the first certificate that is not consistent
			selectedCert = cert
			continue
		}
		certsForDeletion = append(certsForDeletion, cert)
	}

	if len(certsForDeletion) > 0 {
		if err = h.DeleteCertificates(ctx, certsForDeletion); err != nil {
			return "", fmt.Errorf("failed to delete outdated certificates for %s: %w", ownerId, err)
		}
	}

	if selectedCert == nil { // create
		err = h.CreateCertificate(ctx, info)
	} else if !consistent { // update
		err = h.UpdateCertificate(ctx, selectedCert, info)
	}

	return
}

func handleAdditionalCACertificate[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, credentialName, credentialNamespace string, ownerId string) error {
	secretName := fmt.Sprintf("%s-cacert", credentialName)

	// Try to get the existing secret
	existingSecret, err := c.kubeClient.CoreV1().Secrets(credentialNamespace).Get(ctx, secretName, metav1.GetOptions{})
	secretExists := err == nil
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get existing secret: %w", err)
	}

	// Extract the additional ca certificate
	caCert := extractAdditionalCACert(dom)
	if caCert == "" {
		if secretExists {
			if err := c.kubeClient.CoreV1().Secrets(credentialNamespace).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete stale ca certificate secret %s for %s: %w", secretName, ownerId, err)
			}
		}
		return nil
	}

	// Prepare new secret data
	secretData := map[string][]byte{
		"ca.crt": []byte(caCert),
	}
	secretDataHash, err := serializeAndHash(secretData)
	if err != nil {
		return fmt.Errorf("failed to serialize additional ca certificate data for %s: %w", ownerId, err)
	}

	if secretExists {
		// Skip update if the hash hasn't changed
		if existingSecret.Annotations[AnnotationResourceHash] == secretDataHash {
			return nil
		}

		// update the existing secret
		existingSecret.Data = secretData
		existingSecret.Annotations[AnnotationResourceHash] = secretDataHash
		existingSecret.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
		if _, err := c.kubeClient.CoreV1().Secrets(credentialNamespace).Update(ctx, existingSecret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update additional ca certificate secret for %s: %w", ownerId, err)
		}
		return nil
	}

	return createAdditionalCACertificateSecret(ctx, c, secretName, credentialNamespace, secretData, map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
		LabelOwnerGeneration:     fmt.Sprintf("%d", dom.GetMetadata().Generation),
	}, map[string]string{
		AnnotationResourceHash:    secretDataHash,
		AnnotationOwnerIdentifier: ownerId,
	})
}

func extractAdditionalCACert[T v1alpha1.DomainEntity](dom T) string {
	if dom.GetSpec().CertConfig != nil {
		return dom.GetSpec().CertConfig.AdditionalCACertificate
	}
	return ""
}

func createAdditionalCACertificateSecret(ctx context.Context, c *Controller, name, namespace string, secretData map[string][]byte, labels, annotations map[string]string) error {
	// create a secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: secretData,
		Type: corev1.SecretTypeOpaque,
	}

	if _, err := c.kubeClient.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create additional ca certificate secret for %s: %w", annotations[AnnotationOwnerIdentifier], err)
	}

	return nil
}

// #region Ingress Gateway Info
func getIngressInfo[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T) (ingGwInfo *ingressGatewayInfo, err error) {
	// create ingress gateway selector from specified labels
	ingressLabelSelector, err := labels.ValidatedSelectorFromSet(dom.GetSpec().IngressSelector)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			c.Event(runtime.Object(dom), nil, corev1.EventTypeWarning, DomainEventMissingIngressGatewayInfo, EventActionProcessingDomainResources, err.Error())
		}
	}()

	// Get relevant ingress gateway pods
	ingressPods, err := c.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: ingressLabelSelector.String()})
	if err != nil {
		return nil, err
	}

	// Determine relevant ingress gateway namespace
	var namespace string
	ownerId := formOwnerIdFromDomain(dom)
	// Create a dummy lookup map for determining relevant pods
	relevantPodNames := map[string]struct{}{}
	for _, pod := range ingressPods.Items {
		// We only support 1 ingress gateway pod namespace as of now! (Multiple pods e.g. replicas can exist in the same namespace)
		if namespace == "" {
			namespace = pod.Namespace
		} else if namespace != pod.Namespace {
			return nil, fmt.Errorf("more than one matching ingress gateway namespace found matching selector from %s", ownerId)
		}
		relevantPodNames[pod.Name] = struct{}{}
	}
	if namespace == "" {
		return nil, fmt.Errorf("no matching ingress gateway pods found matching selector from %s", ownerId)
	}

	// Identify dns target
	// (1) look for explicitly specified dns target
	dnsTarget := dom.GetSpec().DNSTarget
	// (2) attempt to get dn target from environment (Kyma use case)
	if dnsTarget == "" {
		dnsTarget = envDNSTarget()
	}
	// (3) attempt to get dns target from Service via annotation(s)
	if dnsTarget == "" {
		dnsTarget, err = getDNSTargetFromIngressLoadbalancerService(ctx, c, namespace, relevantPodNames, dom)
		if err != nil {
			return nil, err
		}
	}
	if dnsTarget == "" {
		return nil, fmt.Errorf("ingress service not annotated with dns target name for %s", ownerId)
	}

	// Return ingress Gateway info (Namespace and DNS target)
	return &ingressGatewayInfo{Namespace: namespace, DNSTarget: dnsTarget}, nil
}

func getDNSTargetFromIngressLoadbalancerService[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, namespace string, relevantPodNames map[string]struct{}, dom T) (string, error) {
	loadbalancerServices, err := c.getLoadBalancerServices(ctx, namespace)
	if err != nil {
		return "", err
	}

	list, err := c.kubeClient.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	loadbalancerSvc := getRelevantLoadBalancerService(list.Items, loadbalancerServices, relevantPodNames)
	if loadbalancerSvc != nil {
		return getDNSTarget(loadbalancerSvc), nil
	}

	return "", fmt.Errorf("no matching load balancer service found for %s", formOwnerIdFromDomain(dom))
}

func getRelevantLoadBalancerService(endpointSlices []discoveryv1.EndpointSlice, loadbalancerServices []corev1.Service, relevantPodNames map[string]struct{}) *corev1.Service {
	for _, slice := range endpointSlices {
		serviceName := slice.Labels[LabelKubernetesServiceName]
		if serviceName == "" {
			continue
		}
		svcIndex := slices.IndexFunc(loadbalancerServices, func(svc corev1.Service) bool { return svc.Name == serviceName })
		if svcIndex < 0 {
			// this Endpoint / service is not relevant
			continue
		}

		for _, ep := range slice.Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
				if _, ok := relevantPodNames[ep.TargetRef.Name]; ok {
					return &loadbalancerServices[svcIndex]
				}
			}
		}
	}
	// no relevant service found
	return nil
}

func (c *Controller) getLoadBalancerServices(ctx context.Context, istioIngressGWNamespace string) ([]corev1.Service, error) {
	// List all services in the same namespace as the istio-ingressgateway pod namespace
	allServices, err := c.kubeClient.CoreV1().Services(istioIngressGWNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	// Filter out LoadBalancer services
	loadBalancerSvcs := []corev1.Service{}
	for _, svc := range allServices.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			loadBalancerSvcs = append(loadBalancerSvcs, svc)
		}
	}
	return loadBalancerSvcs, nil
}

func getDNSTarget(ingressGWSvc *corev1.Service) string {
	var dnsTarget string
	switch dnsManager() {
	case dnsManagerGardener:
		dnsTarget = ingressGWSvc.Annotations[AnnotationGardenerDNSTarget]
	case dnsManagerKubernetes:
		dnsTarget = ingressGWSvc.Annotations[AnnotationKubernetesDNSTarget]
	}

	// Use the 1st value from Comma separated values (if any)
	return strings.Split(dnsTarget, ",")[0]
}

//#endregion

func formOwnerIdFromDomain[T v1alpha1.DomainEntity](dom T) string {
	ownerId := dom.GetKind()
	if ownerId == v1alpha1.DomainKind {
		ownerId = ownerId + "." + dom.GetNamespace()
	}
	ownerId = ownerId + "." + dom.GetName()
	return ownerId
}

func getResourceKeyFromKind[T v1alpha1.DomainEntity](dom T) int {
	switch dom.GetKind() {
	case v1alpha1.DomainKind:
		return ResourceDomain
	default:
		return ResourceClusterDomain
	}
}

func getReferencingApplications[T v1alpha1.DomainEntity](c *Controller, dom T) ([]*v1alpha1.CAPApplication, error) {
	cas, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list CAPApplications: %w", err)
	}
	sources := []*v1alpha1.CAPApplication{}
	for i := range cas {
		ca := cas[i]
		if dom.GetKind() == v1alpha1.DomainKind && ca.Namespace != dom.GetNamespace() {
			continue // skip application if it is not in the same namespace
		}
		if len(ca.Spec.DomainRefs) == 0 {
			continue
		}
		referenced := false
		for _, ref := range ca.Spec.DomainRefs {
			if ref.Kind == dom.GetKind() && ref.Name == dom.GetName() {
				referenced = true
				break
			}
		}
		if !referenced {
			continue
		}
		sources = append(sources, ca)
	}
	return sources, nil
}

func handleDomainNetworkPolicies[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, ownerId, subResourceName string) (err error) {
	cas, err := getReferencingApplications(c, dom)
	if err != nil {
		return err
	}
	appNamespaces := map[string]*k8snwv1.NetworkPolicy{}
	for i := range cas {
		appNamespaces[cas[i].Namespace] = nil
	}

	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})
	list, err := c.kubeClient.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return fmt.Errorf("failed to list network policies for %s: %w", ownerId, err)
	}

	netpolsForDeletion := []k8snwv1.NetworkPolicy{}
	for i := range list.Items {
		netpol := list.Items[i]
		if existing, ok := appNamespaces[netpol.Namespace]; ok && existing == nil {
			// select this network policy as the one to be maintained
			appNamespaces[netpol.Namespace] = &netpol
		} else {
			netpolsForDeletion = append(netpolsForDeletion, netpol)
		}
	}

	if len(netpolsForDeletion) > 0 {
		// delete outdated network policies
		delGrp, delCtx := errgroup.WithContext(ctx)
		for i := range netpolsForDeletion {
			netpol := netpolsForDeletion[i]
			delGrp.Go(func() error {
				return c.kubeClient.NetworkingV1().NetworkPolicies(netpol.Namespace).Delete(delCtx, netpol.Name, metav1.DeleteOptions{})
			})
		}
		if err = delGrp.Wait(); err != nil {
			return fmt.Errorf("failed to delete outdated network policies for %s: %w", ownerId, err)
		}
	}

	// create or update network policies for the remaining namespaces
	updGrp, updCtx := errgroup.WithContext(ctx)
	for namespace := range appNamespaces {
		netpol := appNamespaces[namespace]
		updGrp.Go(func() error {
			return handleDomainNetworkPolicyForNamespace(updCtx, c, dom, ownerId, subResourceName, namespace, netpol)
		})
	}
	return updGrp.Wait()
}

func handleDomainNetworkPolicyForNamespace[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, ownerId, subResourceName, namespace string, netpol *k8snwv1.NetworkPolicy) (err error) {
	spec := k8snwv1.NetworkPolicySpec{
		PolicyTypes: []k8snwv1.PolicyType{k8snwv1.PolicyTypeIngress},
		PodSelector: metav1.LabelSelector{ // to workload pods managed by the operator
			MatchLabels: map[string]string{
				LabelExposedWorkload:  "true",
				LabelResourceCategory: CategoryWorkload,
			},
		},
		Ingress: []k8snwv1.NetworkPolicyIngressRule{ // from the ingress pods matching the specified selector
			{
				From: []k8snwv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: dom.GetSpec().IngressSelector,
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
	}

	hash, err := serializeAndHash(spec)
	if err != nil {
		return fmt.Errorf("failed to serialize network policy spec in namespace %s for %s: %w", namespace, ownerId, err)
	}

	if netpol == nil { // create network policy
		_, err = c.kubeClient.NetworkingV1().NetworkPolicies(namespace).Create(ctx, &k8snwv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: subResourceName + "-",
				Namespace:    namespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash: sha1Sum(ownerId),
					LabelOwnerGeneration:     fmt.Sprintf("%d", dom.GetMetadata().Generation),
				},
				Annotations: map[string]string{
					AnnotationResourceHash:    hash,
					AnnotationOwnerIdentifier: ownerId,
				},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(metav1.Object(dom), v1alpha1.SchemeGroupVersion.WithKind(dom.GetKind())),
				},
			},
			Spec: spec,
		}, metav1.CreateOptions{})
	} else { // update network policy
		updateResourceAnnotation(&netpol.ObjectMeta, hash)
		netpol.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
		netpol.Spec = spec
		_, err = c.kubeClient.NetworkingV1().NetworkPolicies(namespace).Update(ctx, netpol, metav1.UpdateOptions{})
	}

	return err
}

func fetchDomainResourcesFromCache(c *Controller, refs []v1alpha1.DomainRef, namespace string) ([]*v1alpha1.Domain, []*v1alpha1.ClusterDomain, error) {
	doms := []*v1alpha1.Domain{}
	cdoms := []*v1alpha1.ClusterDomain{}
	for _, ref := range refs {
		switch ref.Kind {
		case v1alpha1.DomainKind:
			dom, err := c.crdInformerFactory.Sme().V1alpha1().Domains().Lister().Domains(namespace).Get(ref.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get domain %s.%s: %w", namespace, ref.Name, err)
			}
			doms = append(doms, dom)
		case v1alpha1.ClusterDomainKind:
			cdom, err := c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister().ClusterDomains(corev1.NamespaceAll).Get(ref.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get cluster domain %s: %w", ref.Name, err)
			}
			cdoms = append(cdoms, cdom)
		}
	}

	return doms, cdoms, nil
}

func getDomainHosts[T v1alpha1.DomainEntity](s []T, subdomain string) []string {
	hosts := []string{}
	for _, dom := range s {
		v := dom.GetSpec().Domain
		if subdomain != "" {
			v = subdomain + "." + v
		}
		hosts = append(hosts, v)
	}
	return hosts
}

func getDomainGatewayReferences[T v1alpha1.DomainEntity](s []T) []string {
	gateways := []string{}

	for _, dom := range s {
		if dom.GetStatus().GatewayName != "" {
			if dom.GetKind() == v1alpha1.DomainKind {
				gateways = append(gateways, dom.GetStatus().GatewayName)
			} else {
				// for ClusterDomain, the gateway name is prefixed with the operator namespace
				gateways = append(gateways, util.GetNamespace()+"/"+dom.GetStatus().GatewayName)
			}
		}
	}
	return gateways
}

func areDomainResourcesReady[T v1alpha1.DomainEntity](doms []T) (bool, error) {
	if len(doms) == 0 {
		return true, nil
	}
	for _, dom := range doms {
		s := dom.GetStatus()
		if s.State == v1alpha1.DomainStateError {
			return false, fmt.Errorf("%s in state %s: %s", formOwnerIdFromDomain(dom), s.State, dom.GetStatusReadyConditionMessage())
		}
		if !isCROConditionReady(s.GenericStatus) {
			return false, nil
		}
	}
	return true, nil
}

func deleteDomainCertificates[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, _ T, ownerId string) error {
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})
	h := CreateCertificateManager(c)
	certs, err := h.ListCertificates(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		return fmt.Errorf("failed to list certificates for %s: %w", ownerId, err)
	}
	if len(certs) == 0 {
		return nil
	}

	if err = h.DeleteCertificates(ctx, certs); err != nil {
		return fmt.Errorf("failed to delete certificates for %s: %w", ownerId, err)
	}
	return nil
}

func deleteAdditionalCACertificateSecret[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, _ T, ownerId string) error {
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})

	// Try to get the existing secret using the selector
	secretList, err := c.kubeClient.CoreV1().Secrets(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to list additional ca certificate secrets for %s: %w", ownerId, err)
	}
	if len(secretList.Items) == 0 {
		// No secret found, nothing to delete
		return nil
	}

	// Delete all secrets matching the selector
	for _, secret := range secretList.Items {
		if err := c.kubeClient.CoreV1().Secrets(secret.Namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete additional ca certificate secret %s.%s for %s: %w", secret.Namespace, secret.Name, ownerId, err)
		}
	}

	return nil
}

func handleDomainResourceDeletion[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T) (*ReconcileResult, error) {
	cas, err := getReferencingApplications(c, dom)
	if err != nil {
		return nil, err
	}

	var readyStatus metav1.ConditionStatus
	if isCROConditionReady(dom.GetStatus().GenericStatus) {
		readyStatus = metav1.ConditionTrue
	} else {
		readyStatus = metav1.ConditionFalse
	}

	if len(cas) > 0 {
		// keep ready condition intact - block deletion
		dom.SetStatusWithReadyCondition(v1alpha1.DomainStateDeleting, readyStatus, "DeletionBlocked", "deletion blocked by referencing applications")
		// requeue to attempt after a delay
		return NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 30*time.Second), nil
	}

	if dom.GetStatus().State != v1alpha1.DomainStateDeleting || readyStatus == metav1.ConditionTrue {
		dom.SetStatusWithReadyCondition(v1alpha1.DomainStateDeleting, metav1.ConditionFalse, "Deleting", "deleting domain resources")
		return NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 0), nil
	}

	ownerId := formOwnerIdFromDomain(dom)
	err = deleteDomainCertificates(ctx, c, dom, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete domain certificates for %s: %w", ownerId, err)
	}

	err = deleteAdditionalCACertificateSecret(ctx, c, dom, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete additional ca certificate secret for %s: %w", ownerId, err)
	}

	// remove finalizer from domain
	if removeFinalizer(&dom.GetMetadata().Finalizers, FinalizerDomain) {
		switch v := any(dom).(type) {
		case *v1alpha1.Domain:
			err = c.updateDomain(ctx, v)
		case *v1alpha1.ClusterDomain:
			err = c.updateClusterDomain(ctx, v)

		}
	}

	return nil, err
}

func createDomainMap[T v1alpha1.DomainEntity](doms []T, in map[string]string) (out map[string]string) {
	out = in
	if out == nil {
		out = map[string]string{}
	}
	for _, dom := range doms {
		out[formOwnerIdFromDomain(dom)] = dom.GetSpec().Domain
	}
	return
}

func convertOwnerIdsToDomainReferences(ownerIds []string) (refs []v1alpha1.DomainRef) {
	refs = []v1alpha1.DomainRef{}
	for _, id := range ownerIds {
		parts := strings.Split(id, ".")
		switch len(parts) {
		case 2:
			refs = append(refs, v1alpha1.DomainRef{Kind: parts[0], Name: parts[1]})
		default: // case 3:
			refs = append(refs, v1alpha1.DomainRef{Kind: parts[0], Name: parts[2]})
		}
	}
	return
}

func sanitizeDNSTarget(dnsTarget string) string {
	// Replace *.domain with x.domain as * is not a valid subdomain for a dns target
	return strings.ReplaceAll(dnsTarget, "*", "x")
}
