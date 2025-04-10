package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	dnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
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
	"k8s.io/apimachinery/pkg/selection"
)

const (
	DomainEventMissingIngressGatewayInfo = "MissingIngressGatewayInfo"
	DomainEventSubdomainAlreadyInUse     = "SubdomainAlreadyInUse"
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
	defer func() {
		if err != nil {
			dom.SetStatusWithReadyCondition(v1alpha1.DomainStateError, metav1.ConditionFalse, "ProcessingError", err.Error())
		}
	}()

	if dom.GetStatus().State == v1alpha1.DomainStateReady {
		// set processing status
		dom.SetStatusWithReadyCondition(v1alpha1.DomainStateProcessing, metav1.ConditionFalse, "Processing", "Processing domain resources")
		return NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 0), nil
	}

	ownerId := formOwnerIdFromDomain(dom)
	subResourceName := fmt.Sprintf("%s-%s", subResourceNamespace, dom.GetName())

	// (1) get ingress information
	var (
		ingressInfo *ingressGatewayInfo
	)
	ingressInfo, err = getIngressInfo(ctx, c, dom)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingress information for %s: %w", ownerId, err)
	}
	dom.GetStatus().DnsTarget = ingressInfo.DNSTarget

	// (2) reconcile certificate
	err = handleDomainCertificate(ctx, c, dom, subResourceName, ingressInfo.Namespace, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain certificate for %s: %w", ownerId, err)
	}

	// (3) reconcile gateway
	err = handleDomainGateway(ctx, c, dom, subResourceName, subResourceNamespace, ownerId)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain gateway for %s: %w", ownerId, err)
	}

	// (4) handle dns entries
	err = handleDnsEntries(ctx, c, dom, ownerId, subResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile domain dns entries for %s: %w", ownerId, err)
	}

	// (5) wait for certificate to be ready
	if ready, err := areCertificatesReady(ctx, c, []T{dom}); err != nil || !ready {
		if err == nil {
			result = NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 3*time.Second)
		}
		return result, err
	}

	// (6) wait for dns entries to be ready
	if ready, err := areDnsEntriesReady(ctx, c, []T{dom}, ""); err != nil || !ready {
		if err == nil {
			result = NewReconcileResultWithResource(getResourceKeyFromKind(dom), dom.GetName(), dom.GetNamespace(), 3*time.Second)
		}
		return result, err
	}

	dom.SetStatusWithReadyCondition(v1alpha1.DomainStateReady, metav1.ConditionTrue, "Ready", "Domain resources are ready")
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

func handleDomainGateway[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, name, namespace, ownerId string) (err error) {
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

func handleDomainCertificate[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, name, namespace, ownerId string) (err error) {
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
		ingressService, err := getIngressLoadbalancerService(ctx, c, namespace, relevantPodNames, dom)
		if err != nil {
			return nil, err
		}
		if ingressService != nil {
			dnsTarget = getDNSTarget(ingressService)
		}
	}
	if dnsTarget == "" {
		return nil, fmt.Errorf("ingress service not annotated with dns target name for %s", ownerId)
	}

	// Return ingress Gateway info (Namespace and DNS target)
	return &ingressGatewayInfo{Namespace: namespace, DNSTarget: dnsTarget}, nil
}

func getIngressLoadbalancerService[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, namespace string, relevantPodNames map[string]struct{}, dom T) (*corev1.Service, error) {
	list, err := c.kubeClient.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ownerId := formOwnerIdFromDomain(dom)
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
		return nil, fmt.Errorf("no matching services found for %s", ownerId)
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

	return nil, fmt.Errorf("no matching load balancer service found for %s", ownerId)
}

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

func handleDnsEntries[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, ownerId, subResourceNamespace string) (err error) {
	list, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			LabelOwnerIdentifierHash: sha1Sum(ownerId),
		}).String(),
	})
	if err != nil {
		return fmt.Errorf("failed to list dns entries for %s: %w", ownerId, err)
	}

	// list of subdomains for which dns entries need to be created
	subdomains := map[string]map[string]string{}
	subdomainHashes := map[string]string{}
	listComplete := false

	switch dom.GetSpec().DNSMode {
	case v1alpha1.DnsModeNone:
		listComplete = true
	case v1alpha1.DnsModeWildcard:
		sh := sha1Sum("*")
		subdomains["*"] = map[string]string{
			LabelSubdomainHash: sh,
		}
		subdomainHashes[sh] = "*"
		listComplete = true
	case v1alpha1.DnsModeSubdomain:
		// find subdomains from applications in the next step
	}

	if !listComplete {
		cas, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().List(labels.Everything())
		if err != nil {
			return fmt.Errorf("failed to list CAPApplications: %w", err)
		}
		for _, ca := range cas {
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

			if len(ca.Status.ObservedSubdomains) > 0 {
				for _, subdomain := range ca.Status.ObservedSubdomains {
					if deLabels, ok := subdomains[subdomain]; !ok {
						sh := sha1Sum(subdomain)
						subdomains[subdomain] = map[string]string{
							LabelSubdomainHash:                sha1Sum(subdomain),
							LabelBTPApplicationIdentifierHash: ca.Labels[LabelBTPApplicationIdentifierHash],
						}
						subdomainHashes[sh] = subdomain
					} else if deLabels[LabelBTPApplicationIdentifierHash] != ca.Labels[LabelBTPApplicationIdentifierHash] {
						// this subdomain is already used by another application
						// skip and raise warning event
						c.Event(ca, runtime.Object(dom), corev1.EventTypeWarning, DomainEventSubdomainAlreadyInUse, EventActionProcessingDomainResources,
							fmt.Sprintf("Subdomain %s is already used by another application with domain %s (%s)", subdomain, ownerId, dom.GetSpec().Domain))
					}
				}
			}
		}
		listComplete = true
	}

	// update relevant existing dns entries
	for _, entry := range list.Items {
		if sh, ok := entry.Labels[LabelSubdomainHash]; ok {
			if sdom, ok := subdomainHashes[sh]; ok {
				deLabels := subdomains[sdom]
				appId := deLabels[LabelBTPApplicationIdentifierHash]
				// update dns entry
				hash := sha256Sum(dom.GetSpec().Domain, sdom, dom.GetStatus().DnsTarget, appId)
				if entry.Annotations[AnnotationResourceHash] != hash {
					updateResourceAnnotation(&entry.ObjectMeta, hash)
					entry.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", dom.GetMetadata().Generation)
					entry.Labels[LabelBTPApplicationIdentifierHash] = appId
					entry.Spec = dnsv1alpha1.DNSEntrySpec{
						DNSName: sdom + "." + dom.GetSpec().Domain,
						Targets: []string{dom.GetStatus().DnsTarget},
					}
					_, err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(entry.Namespace).Update(ctx, &entry, metav1.UpdateOptions{})
					if err != nil {
						return fmt.Errorf("failed to update dns entry %s.%s: %w", entry.Namespace, entry.Name, err)
					}
				}
				delete(subdomains, sdom)
			}
		}
	}

	// create new dns entries
	for sdom, deLabels := range subdomains {
		appId := deLabels[LabelBTPApplicationIdentifierHash]
		hash := sha256Sum(dom.GetSpec().Domain, sdom, dom.GetStatus().DnsTarget, appId)
		dnsEntry := &dnsv1alpha1.DNSEntry{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-%s-", subResourceNamespace, dom.GetName()),
				Namespace:    subResourceNamespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash:          sha1Sum(ownerId),
					LabelOwnerGeneration:              fmt.Sprintf("%d", dom.GetMetadata().Generation),
					LabelSubdomainHash:                sha1Sum(sdom),
					LabelBTPApplicationIdentifierHash: appId,
				},
				Annotations: map[string]string{
					AnnotationResourceHash:     hash,
					AnnotationOwnerIdentifier:  ownerId,
					GardenerDNSClassIdentifier: GardenerDNSClassValue,
				},
				// Finalizers: []string{FinalizerDomain},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(metav1.Object(dom), v1alpha1.SchemeGroupVersion.WithKind(dom.GetKind())),
				},
			},
			Spec: dnsv1alpha1.DNSEntrySpec{
				DNSName:             sdom + "." + dom.GetSpec().Domain,
				Targets:             []string{dom.GetStatus().DnsTarget},
				CNameLookupInterval: &cNameLookup,
				TTL:                 &ttl,
			},
		}
		_, err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).Create(ctx, dnsEntry, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create dns entry for subdomain %s: %w", sdom, err)
		}
	}

	// delete outdated dns entries
	// Add a requirement for OwnerIdentifierHash and SubdomainHash
	ownerReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{sha1Sum(ownerId)})
	subDomainExistsReq, _ := labels.NewRequirement(LabelSubdomainHash, selection.Exists, []string{})
	// Create label selector based on the above requirement for filtering out all outdated dns entries
	deletionSelector := labels.NewSelector().Add(*ownerReq, *subDomainExistsReq)
	if len(subdomainHashes) > 0 {
		// Add all unused subdomain hashes to requirements for Label Selector
		hashes := slices.Collect(maps.Keys(subdomainHashes))
		subDomainsReq, _ := labels.NewRequirement(LabelSubdomainHash, selection.NotIn, hashes)
		deletionSelector = deletionSelector.Add(*subDomainsReq)
	}

	return c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: deletionSelector.String()})
}

func areCertificatesReady[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, doms []T) (ready bool, err error) {
	ownerIdHashes := []string{}
	domainMap := map[string]T{}
	for i := range doms {
		hash := sha1Sum(formOwnerIdFromDomain(doms[i]))
		ownerIdHashes = append(ownerIdHashes, hash)
		domainMap[hash] = doms[i]
	}
	selector := newSelectorForOwnerIdentifierHashes(ownerIdHashes)
	certs, err := c.gardenerCertificateClient.CertV1alpha1().Certificates(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return false, fmt.Errorf("failed to list certificates: %w", err)
	}

	for _, cert := range certs.Items {
		if dom, ok := domainMap[cert.Labels[LabelOwnerIdentifierHash]]; ok {
			// check for ready state
			if cert.Status.State == certv1alpha1.StateError {
				return false, fmt.Errorf("%s has state %s for %s: %s", certv1alpha1.CertificateKind, certv1alpha1.StateError, formOwnerIdFromDomain(dom), *cert.Status.Message)
			} else if cert.Status.State != certv1alpha1.StateReady {
				return false, nil
			}
		} else {
			// expected related domain for the certificate
			return false, fmt.Errorf("failed to match domain for certificate %s.%s", cert.Namespace, cert.Name)
		}
		delete(domainMap, cert.Labels[LabelOwnerIdentifierHash])
	}

	if len(domainMap) > 0 {
		// not all domains have a certificate
		return false, nil
	}

	return true, nil
}

func areDnsEntriesReady[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, doms []T, subdomain string) (ready bool, err error) {
	ownerIdHashes := []string{}
	domainMap := map[string]T{}
	for i := range doms {
		switch doms[i].GetSpec().DNSMode {
		case v1alpha1.DnsModeNone:
			// skip dns entry check for domains with dns mode none
			continue
		case v1alpha1.DnsModeWildcard:
			// skip dns entry check for domains with dns mode mode wildcard when a specific subdomain is provided
			if subdomain != "" {
				continue
			}
		}
		hash := sha1Sum(formOwnerIdFromDomain(doms[i]))
		ownerIdHashes = append(ownerIdHashes, hash)
		domainMap[hash] = doms[i]
	}
	selector := newSelectorForOwnerIdentifierHashes(ownerIdHashes)
	if subdomain != "" {
		// add subdomain hash to the selector
		subdomainHash := sha1Sum(subdomain)
		subdomainReq, _ := labels.NewRequirement(LabelSubdomainHash, selection.Equals, []string{subdomainHash})
		selector = selector.Add(*subdomainReq)
	}

	// list all dns entries which match the the domains (and subdomain, if supplied)
	dnsEntries, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return false, fmt.Errorf("failed to list dns entries: %w", err)
	}
	for _, entry := range dnsEntries.Items {
		dom, ok := domainMap[entry.Labels[LabelOwnerIdentifierHash]]
		if !ok {
			// expected related domain for the dns entry
			return false, fmt.Errorf("failed to match domain for dns entry %s.%s", entry.Namespace, entry.Name)
		}
		// check for ready state
		if entry.Status.State == dnsv1alpha1.STATE_ERROR {
			return false, fmt.Errorf("%s in state %s for %s: %s", dnsv1alpha1.DNSEntryKind, dnsv1alpha1.STATE_ERROR, formOwnerIdFromDomain(dom), *entry.Status.Message)
		} else if entry.Status.State != dnsv1alpha1.STATE_READY {
			return false, nil
		}
	}

	return true, nil
}

func newSelectorForOwnerIdentifierHashes(ownerIdHashes []string) labels.Selector {
	ownerReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.In, ownerIdHashes)
	return labels.NewSelector().Add(*ownerReq)
}

func fetchDomainResourcesFromCache(ctx context.Context, c *Controller, refs []v1alpha1.DomainRefs, namespace string) ([]*v1alpha1.Domain, []*v1alpha1.ClusterDomain, error) {
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
	operatorNamespace := util.GetNamespace()
	for _, dom := range s {
		if dom.GetKind() == v1alpha1.DomainKind {
			gateways = append(gateways, fmt.Sprintf("%s-%s", dom.GetNamespace(), dom.GetName()))
		} else {
			gateways = append(gateways, fmt.Sprintf("%s/%s-%s", operatorNamespace, operatorNamespace, dom.GetName()))
		}
	}
	return gateways
}

func areDomainResourcesReady[T v1alpha1.DomainEntity](doms []T) bool {
	if len(doms) == 0 {
		return true
	}
	for _, dom := range doms {
		s := dom.GetStatus()
		if s.State != v1alpha1.DomainStateReady || !isCROConditionReady(s.GenericStatus) {
			return false
		}
	}
	return true
}
