package controller

import (
	"context"
	"fmt"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/sync/errgroup"
	networkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

const (
	DomainEventMissingIngressGatewayInfo = "MissingIngressGatewayInfo"
	EventActionProcessingDomainResources = "ProcessingDomainResources"
	LabelKubernetesServiceName           = "kubernetes.io/service-name"
)

func (c *Controller) reconcileDomain(ctx context.Context, item QueueItem, attempts int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().Domains().Lister()
	cached, err := lister.Domains(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	dom := cached.DeepCopy()

	// prepare finalizers
	if prepareDomainEntity(ctx, c, dom) {
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

func (c *Controller) reconcileClusterDomain(ctx context.Context, item QueueItem, attempts int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister()
	cached, err := lister.ClusterDomains(corev1.NamespaceAll).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	dom := cached.DeepCopy()

	// prepare finalizers
	if prepareDomainEntity(ctx, c, dom) {
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
	// set processing status
	dom.SetStatusWithReadyCondition(v1alpha1.DomainStateProcessing, metav1.ConditionFalse, "Processing", "Processing domain resources")

	defer func() {
		if err != nil {
			dom.SetStatusWithReadyCondition(v1alpha1.DomainStateError, metav1.ConditionFalse, "Processing", err.Error())
		}
	}()

	subResourceName := fmt.Sprintf("%s-%s", subResourceNamespace, dom.GetName())
	// (1) get ingress information
	var (
		ingressInfo *ingressGatewayInfo
	)
	ingressInfo, err = getIngressInfo(ctx, c, dom)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingress information for %s: %w", formOwnerIdFromDomain(dom), err)
	}
	dom.GetStatus().DnsTarget = ingressInfo.DNSTarget

	// (2) reconcile certificate
	err = handleDomainCertificate(ctx, c, dom, subResourceName, ingressInfo.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain certificate for %s: %w", subResourceName, err)
	}

	// (3) reconcile gateway
	err = handleDomainGateway(ctx, c, dom, subResourceName, subResourceNamespace)

	// (4) handle dns entries

	// (5) wait for certificate to be ready

	// (6) wait for dns entries to be ready

	return
}

func prepareDomainEntity[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T) (update bool) {
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

	return update
}

func handleDomainGateway[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, name, namespace string) (err error) {
	ownerId := formOwnerIdFromDomain(dom)
	gateway, err := c.istioClient.NetworkingV1().Gateways(namespace).Get(ctx, name, metav1.GetOptions{})
	found := !errors.IsNotFound(err)
	if err != nil && found {
		return fmt.Errorf("failed to get gateway for %s: %w", ownerId, err)
	}

	if found && gateway.Labels[LabelOwnerIdentifierHash] != sha1Sum(ownerId) {
		// this gateway is not owned by the domain
		return fmt.Errorf("gateway %s.%s is not owned by %s", gateway.Namespace, gateway.Name, ownerId)
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
					CredentialName: name,
				},
			},
		},
	}
	hash, err := serializeAndHash(gatewaySpec)
	if err != nil {
		return fmt.Errorf("failed to serialize gateway spec: %w", err)
	}

	if !found { // create
		_, err = c.istioClient.NetworkingV1().Gateways(namespace).Create(ctx, &istionwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
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
			Spec: *gatewaySpec,
		}, metav1.CreateOptions{})
	} else if gateway.Labels[AnnotationResourceHash] != hash { // update
		updateResourceAnnotation(&gateway.ObjectMeta, hash)
		gateway.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
		gateway.Spec = *gatewaySpec
		_, err = c.istioClient.NetworkingV1().Gateways(namespace).Update(ctx, gateway, metav1.UpdateOptions{})
	}

	return
}

func handleDomainCertificate[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, name, namespace string) (err error) {
	ownerId := formOwnerIdFromDomain(dom)
	klog.Infof("[********] %s: %s", dom.GetKind(), ownerId)
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})
	certs, err := c.gardenerCertificateClient.CertV1alpha1().Certificates(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to list certificates for %s: %w", ownerId, err)
	}

	certSpec := certv1alpha1.CertificateSpec{
		DNSNames: []string{"*." + dom.GetSpec().Domain},
		SecretRef: &corev1.SecretReference{
			Name:      name,
			Namespace: namespace,
		},
	}
	hash, err := serializeAndHash(certSpec)
	if err != nil {
		return err
	}

	certsForDeletion := []certv1alpha1.Certificate{}
	var (
		selectedCert *certv1alpha1.Certificate
		consistent   bool
	)
	for i := range certs.Items {
		cert := certs.Items[i]
		if cert.Namespace != namespace || consistent {
			certsForDeletion = append(certsForDeletion, cert)
			continue
		}
		if cert.Annotations[AnnotationResourceHash] == hash {
			// this certificate is already up to date
			if selectedCert != nil {
				certsForDeletion = append(certsForDeletion, *selectedCert)
			}
			selectedCert = &cert
			consistent = true
			continue
		}
		if selectedCert == nil {
			// this is the first certificate that is not consistent
			selectedCert = &cert
			continue
		}
		certsForDeletion = append(certsForDeletion, cert)
	}

	if len(certsForDeletion) > 0 {
		delGroup, delCtx := errgroup.WithContext(ctx)
		for i := range certsForDeletion {
			delGroup.Go(func() error {
				cert := &certsForDeletion[i]
				return c.gardenerCertificateClient.CertV1alpha1().Certificates(cert.Namespace).Delete(delCtx, cert.Name, metav1.DeleteOptions{})
			})
		}
		if err = delGroup.Wait(); err != nil {
			return fmt.Errorf("failed to delete outdated certificates for %s: %w", ownerId, err)
		}
	}

	if selectedCert == nil { // create
		cert := &certv1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash: sha1Sum(ownerId),
					LabelOwnerGeneration:     fmt.Sprintf("%d", dom.GetMetadata().Generation),
				},
				Annotations: map[string]string{
					AnnotationResourceHash:    hash,
					AnnotationOwnerIdentifier: ownerId,
				},
				Finalizers: []string{FinalizerDomain},
			},
			Spec: certSpec,
		}
		_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(namespace).Create(ctx, cert, metav1.CreateOptions{})
	} else if !consistent { // update
		updateResourceAnnotation(&selectedCert.ObjectMeta, hash)
		selectedCert.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
		selectedCert.Spec = certSpec
		_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(namespace).Update(ctx, selectedCert, metav1.UpdateOptions{})
	}

	return
}

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
	// Create a dummy lookup map for determining relevant pods
	relevantPodNames := map[string]struct{}{}
	for _, pod := range ingressPods.Items {
		// We only support 1 ingress gateway pod namespace as of now! (Multiple pods e.g. replicas can exist in the same namespace)
		if namespace == "" {
			namespace = pod.Namespace
		} else if namespace != pod.Namespace {
			return nil, fmt.Errorf("more than one matching ingress gateway namespace found matching selector from %s", formOwnerIdFromDomain(dom))
		}
		relevantPodNames[pod.Name] = struct{}{}
	}
	if namespace == "" {
		return nil, fmt.Errorf("no matching ingress gateway pods found matching selector from %s", formOwnerIdFromDomain(dom))
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
		ingressService, err := getIngressLoadbalancerService(ctx, c, namespace, relevantPodNames, dom)
		if err != nil {
			return nil, err
		}
		if ingressService != nil {
			dnsTarget = getDNSTarget(ingressService)
		}
	}
	if dnsTarget == "" {
		return nil, fmt.Errorf("ingress service not annotated with dns target name for %s", formOwnerIdFromDomain(dom))
	}

	// Return ingress Gateway info (Namespace and DNS target)
	return &ingressGatewayInfo{Namespace: namespace, DNSTarget: dnsTarget}, nil
}

func getIngressLoadbalancerService[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, namespace string, relevantPodNames map[string]struct{}, dom T) (*corev1.Service, error) {
	list, err := c.kubeClient.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	serviceTargets := map[string]map[string]struct{}{}
	irrelevantServiceNames := map[string]struct{}{}
	for _, slice := range list.Items {
		serviceName := slice.Labels[LabelKubernetesServiceName]
		if serviceName == "" {
			continue
		}
		if _, ok := irrelevantServiceNames[serviceName]; ok {
			// this service has already been marked as irrelevant
			continue
		}
		entry, ok := serviceTargets[serviceName]
		if !ok {
			entry = map[string]struct{}{}
			serviceTargets[serviceName] = entry
		}
		for _, ep := range slice.Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
				if _, ok := relevantPodNames[ep.TargetRef.Name]; !ok {
					// this endpoint is targets pods outside the relevant selector
					irrelevantServiceNames[serviceName] = struct{}{}
					break
				}
				entry[ep.TargetRef.Name] = struct{}{}
			}
		}
	}
	// remove irrelevant services from the list
	for serviceName := range irrelevantServiceNames {
		delete(serviceTargets, serviceName)
	}
	// if there are no relevant services, return nil
	if len(serviceTargets) == 0 {
		return nil, fmt.Errorf("no matching services found for %s", formOwnerIdFromDomain(dom))
	}

	loadbalancerServices, err := c.getLoadBalancerServices(ctx, namespace)
	if err != nil {
		return nil, err
	}
	for _, svc := range loadbalancerServices {
		if _, ok := serviceTargets[svc.Name]; ok {
			// this load balancer service selects the relevant pods - returning the first matched service
			return &svc, nil
		}
	}

	return nil, fmt.Errorf("no matching load balancer service found for %s", formOwnerIdFromDomain(dom))
}

func formOwnerIdFromDomain[T v1alpha1.DomainEntity](dom T) string {
	ownerId := dom.GetKind()
	if ownerId == v1alpha1.DomainKind {
		ownerId = ownerId + "." + dom.GetNamespace()
	}
	ownerId = ownerId + "." + dom.GetName()
	return ownerId
}
