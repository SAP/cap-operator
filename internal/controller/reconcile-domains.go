/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certManagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	dnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/durationpb"
	networkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// TODO: ignore duplicates reconciliation calls for same dnsTarget, Finalizers... and a whole lot more!

const PrimaryDnsSuffix = "primary-dns"

const (
	CAPOperator              = "CAPOperator"
	OperatorDomainLabel      = CAPOperator + "." + OperatorDomains
	OperatorDomainNamePrefix = "cap-operator-domains-"
)

var (
	cNameLookup = int64(30)
	ttl         = int64(600)
)

const (
	formatResourceState    = "%s in state %s for %s %s.%s"
	formatResourceStateErr = formatResourceState + ": %s"
)

func (c *Controller) handleDomains(ctx context.Context, ca *v1alpha1.CAPApplication) (*ReconcileResult, error) {
	domains, err := json.Marshal(ca.Spec.Domains)
	if err != nil {
		util.LogError(err, "Error occurred while encoding domains to json", string(Processing), ca, nil)
		return nil, fmt.Errorf("error occurred while encoding domains to json: %w", err)
	}
	domainsHash := sha256Sum(string(domains))

	requeue := NewReconcileResult()

	if domainsHash != ca.Status.DomainSpecHash {

		// Reconcile Secondary domains via a dummy resource (separate reconciliation)
		requeue.AddResource(ResourceOperatorDomains, "", metav1.NamespaceAll, 0)
		requeue.AddResource(ResourceCAPApplication, ca.Name, ca.Namespace, 3*time.Second) // requeue CAPApplication for further processing

		// notify tenants of domain specification change (dns entries, virtual services)
		cats, err := c.getRelevantTenantsForCA(ca)
		if err != nil {
			return nil, err
		}
		for _, cat := range cats {
			requeue.AddResource(ResourceCAPTenant, cat.Name, cat.Namespace, 2*time.Second)
		}

		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateProcessing, metav1.ConditionFalse, EventActionProcessingDomainResources, "")
		ca.SetStatusDomainSpecHash(domainsHash)
		return requeue, nil
	}

	return nil, nil
}

func getGatewayServerSpec(domain string, credentialName string) *networkingv1.Server {
	return &networkingv1.Server{
		Hosts: []string{"*." + domain},
		Port: &networkingv1.Port{
			Number:   443,
			Protocol: "HTTPS",
			Name:     domain,
		},
		Tls: &networkingv1.ServerTLSSettings{
			CredentialName: credentialName,
			Mode:           networkingv1.ServerTLSSettings_SIMPLE,
		},
	}
}

func getGardenerCertificateSpec(commonName string, secretName string) certv1alpha1.CertificateSpec {
	return certv1alpha1.CertificateSpec{
		CommonName: &commonName,
		SecretName: &secretName,
	}
}

func getCertManagerCertificateSpec(commonName string, secretName string) certManagerv1.CertificateSpec {
	return certManagerv1.CertificateSpec{
		CommonName: commonName,
		DNSNames:   []string{commonName},
		SecretName: secretName,
		IssuerRef: certManagermetav1.ObjectReference{
			// TODO: make this configurable
			Kind: certManagerv1.ClusterIssuerKind,
			Name: "cluster-ca",
		},
	}
}

func (c *Controller) detectTenantDNSEntryChanges(ctx context.Context, cat *v1alpha1.CAPTenant, ca *v1alpha1.CAPApplication, hash string) (bool, error) {
	labelOwner := map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(v1alpha1.CAPTenantKind, cat.Namespace, cat.Name),
	}
	dnsEntries, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(ca.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(labelOwner).String()})
	if err != nil {
		return false, err
	}
	// When no DNSEntry exists --> assume we might have to create some
	if len(dnsEntries.Items) == 0 {
		return true, nil
	}

	// Detect changes on DNSEntry based on known mismatches (hash / length)
	changeDetected := false
	// length check (primary and secondary)
	if len(dnsEntries.Items) != len(ca.Spec.Domains.Secondary)+1 {
		changeDetected = true
	}
	// hash check
	if !changeDetected {
		for _, dnsEntry := range dnsEntries.Items {
			if dnsEntry.Annotations[AnnotationResourceHash] != hash {
				changeDetected = true
				break
			}
		}
	}
	// Delete all existing DNSEntries
	if changeDetected {
		// Delete all existing DNSEntries
		err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(ca.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(labelOwner).String()})
		if err != nil {
			return false, err
		}
	}

	return changeDetected, nil
}

func (c *Controller) reconcileTenantDNSEntries(ctx context.Context, cat *v1alpha1.CAPTenant) error {
	if dnsManager() != dnsManagerGardener {
		// Not a gardener managed cluster -> return
		return nil
	}
	// get owning CAPApplication
	ca, _ := c.getCachedCAPApplication(cat.Namespace, cat.Spec.CAPApplicationInstance)
	ingressGatewayInfo, err := c.getIngressGatewayInfo(ctx, ca)
	if err != nil {
		return err
	}
	domains := []string{ca.Spec.Domains.Primary}
	domains = append(domains, ca.Spec.Domains.Secondary...)
	dnsTarget := sanitizeDNSTarget(ingressGatewayInfo.DNSTarget)
	hash := sha256Sum(dnsTarget, cat.Spec.SubDomain, strings.Join(domains, ""))
	changeDetected, err := c.detectTenantDNSEntryChanges(ctx, cat, ca, hash)
	if err != nil || !changeDetected {
		return err
	}

	// Create DNS Entries
	for index, domain := range domains {
		dnsEntryName := cat.Name + "-" + strconv.Itoa(index)
		util.LogInfo("Creating dns entry for secondary domain", string(Processing), cat, nil, "dnsEntryName", dnsEntryName, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		_, err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(ca.Namespace).Create(
			ctx, &dnsv1alpha1.DNSEntry{
				ObjectMeta: metav1.ObjectMeta{
					Name: dnsEntryName,
					Annotations: map[string]string{
						GardenerDNSClassIdentifier: GardenerDNSClassValue,
						AnnotationResourceHash:     hash,
						AnnotationOwnerIdentifier:  v1alpha1.CAPTenantKind + "." + cat.Namespace + "." + cat.Name,
					},
					Labels: map[string]string{
						LabelOwnerIdentifierHash: sha1Sum(v1alpha1.CAPTenantKind, cat.Namespace, cat.Name),
					},
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind))},
				},
				Spec: dnsv1alpha1.DNSEntrySpec{
					DNSName: cat.Spec.SubDomain + "." + domain,
					Targets: []string{
						dnsTarget,
					},
				},
			}, metav1.CreateOptions{},
		)
		// Unknown error --> break loop
		if err != nil {
			break
		}
	}
	return err
}

func (c *Controller) checkTenantDNSEntries(ctx context.Context, cat *v1alpha1.CAPTenant) (bool, error) {
	// TODO: ensure that the CAPTenant is set to Ready only once all these DNSEntries are actually ready
	if dnsManager() == dnsManagerGardener {
		// get relevant DNSEntries
		dnsEntries, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(cat.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(KindMap[ResourceCAPTenant], cat.Namespace, cat.Name)}).String()})
		if err != nil {
			return false, err
		}

		if len(dnsEntries.Items) == 0 {
			return false, fmt.Errorf("could not find DNSEntry for %s %s.%s", v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
		}

		for _, dnsEntry := range dnsEntries.Items {
			// check for ready state
			if dnsEntry.Status.State == dnsv1alpha1.STATE_ERROR {
				return false, fmt.Errorf(formatResourceStateErr, dnsv1alpha1.DNSEntryKind, dnsv1alpha1.STATE_ERROR, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name, *dnsEntry.Status.Message)
			} else if dnsEntry.Status.State != dnsv1alpha1.STATE_READY {
				util.LogInfo("DNS entry resource not ready", string(Processing), cat, dnsEntry, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
				return true, nil
			}
		}
	}
	// Not a gardener managed cluster -or- DNSEntries Ready -> return
	return false, nil
}

func (c *Controller) reconcileTenantNetworking(ctx context.Context, cat *v1alpha1.CAPTenant, cavName string, ca *v1alpha1.CAPApplication) (requeue *ReconcileResult, err error) {
	var (
		reason, message        string
		drModified, vsModified bool
		eventType              string = corev1.EventTypeNormal
	)

	defer func() {
		if err != nil {
			eventType = corev1.EventTypeWarning
			message = err.Error()
			if _, ok := err.(*OperatorGatewayMissingError); ok {
				err = nil
				requeue = NewReconcileResultWithResource(ResourceCAPTenant, cat.Name, cat.Namespace, 10*time.Second)
			}
		}
		if reason != "" { // raise event only when there is a modification or problem
			c.Event(cat, nil, eventType, reason, EventActionReconcileTenantNetworking, message)
		}
	}()

	if drModified, err = c.reconcileTenantDestinationRule(ctx, cat, cavName, ca); err != nil {
		util.LogError(err, "Destination rule reconciliation failed", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		reason = CAPTenantEventDestinationRuleModificationFailed
		return
	}

	if vsModified, err = c.reconcileTenantVirtualService(ctx, cat, cavName, ca); err != nil {
		util.LogError(err, "Virtual service reconciliation failed", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		reason = CAPTenantEventVirtualServiceModificationFailed
		return
	}

	// update tenant status
	if drModified || vsModified {
		message = fmt.Sprintf("VirtualService (and DestinationRule) %s.%s was reconciled", cat.Namespace, cat.Name)
		reason = CAPTenantEventTenantNetworkingModified
		conditionStatus := metav1.ConditionFalse
		if isCROConditionReady(cat.Status.GenericStatus) {
			conditionStatus = metav1.ConditionTrue
		}
		cat.SetStatusWithReadyCondition(cat.Status.State, conditionStatus, CAPTenantEventTenantNetworkingModified, message)
	}

	return
}

func (c *Controller) reconcileTenantDestinationRule(ctx context.Context, cat *v1alpha1.CAPTenant, cavName string, ca *v1alpha1.CAPApplication) (modified bool, err error) {
	var (
		create, update bool
		dr             *istionwv1.DestinationRule
	)
	dr, err = c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).Get(ctx, cat.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		dr = &istionwv1.DestinationRule{
			ObjectMeta: metav1.ObjectMeta{
				Name:            cat.Name, // keep the same name as CAPTenant to avoid duplicates
				Namespace:       cat.Namespace,
				Labels:          map[string]string{},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind))},
			},
		}
		create = true
	} else if err != nil {
		return
	}

	if update, err = c.getUpdatedTenantDestinationRuleObject(ctx, cat, dr, cavName); err != nil {
		util.LogError(err, "", string(Processing), cat, dr, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		return
	}

	if create {
		util.LogInfo("Creating destination rule", string(Processing), cat, dr, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		_, err = c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).Create(ctx, dr, metav1.CreateOptions{})
	} else if update {
		util.LogInfo("Updating destination rule", string(Processing), cat, dr, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		_, err = c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).Update(ctx, dr, metav1.UpdateOptions{})
	}

	return create || update, err
}

func (c *Controller) getUpdatedTenantDestinationRuleObject(ctx context.Context, cat *v1alpha1.CAPTenant, dr *istionwv1.DestinationRule, cavName string) (modified bool, err error) {
	// verify owner reference
	modified, err = c.enforceTenantResourceOwnership(&dr.ObjectMeta, &dr.TypeMeta, cat)
	if err != nil {
		return modified, err
	}

	routerPortInfo, err := c.getRouterServicePortInfo(cavName, cat.Namespace)
	if err != nil {
		return modified, err
	}

	spec := &networkingv1.DestinationRule{
		Host: routerPortInfo.WorkloadName + ServiceSuffix + "." + cat.Namespace + ".svc.cluster.local",
		TrafficPolicy: &networkingv1.TrafficPolicy{
			LoadBalancer: &networkingv1.LoadBalancerSettings{
				LbPolicy: &networkingv1.LoadBalancerSettings_ConsistentHash{
					ConsistentHash: &networkingv1.LoadBalancerSettings_ConsistentHashLB{
						HashKey: &networkingv1.LoadBalancerSettings_ConsistentHashLB_HttpCookie{
							HttpCookie: &networkingv1.LoadBalancerSettings_ConsistentHashLB_HTTPCookie{
								Name: RouterHttpCookieName,
								Ttl:  durationpb.New(0 * time.Second),
								Path: "/",
							},
						},
					},
				},
			},
		},
	}

	// check whether changes have to be applied using hash comparison
	serializedSpec, err := json.Marshal(spec)
	if err != nil {
		return modified, fmt.Errorf("error serializing destination rule spec: %s", err.Error())
	}
	hash := sha256Sum(string(serializedSpec))
	if dr.Annotations[AnnotationResourceHash] != hash {
		dr.Spec = *spec
		updateResourceAnnotation(&dr.ObjectMeta, hash)
		modified = true
	}

	return modified, err
}

func (c *Controller) reconcileTenantVirtualService(ctx context.Context, cat *v1alpha1.CAPTenant, cavName string, ca *v1alpha1.CAPApplication) (modified bool, err error) {
	var (
		create, update bool
		vs             *istionwv1.VirtualService
	)

	vs, err = c.istioClient.NetworkingV1().VirtualServices(cat.Namespace).Get(ctx, cat.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		vs = &istionwv1.VirtualService{
			ObjectMeta: metav1.ObjectMeta{
				Name:            cat.Name, // keep the same name as CAPTenant to avoid duplicates
				Namespace:       cat.Namespace,
				Labels:          map[string]string{},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind))},
			},
		}
		create = true
	} else if err != nil {
		return
	}

	if update, err = c.getUpdatedTenantVirtualServiceObject(ctx, cat, vs, cavName, ca); err != nil {
		util.LogError(err, "", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId)
		return
	}

	if create {
		util.LogInfo("Creating virtual service", string(Processing), cat, vs, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		_, err = c.istioClient.NetworkingV1().VirtualServices(cat.Namespace).Create(ctx, vs, metav1.CreateOptions{})
	} else if update {
		util.LogInfo("Updating virtual service", string(Processing), cat, vs, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		_, err = c.istioClient.NetworkingV1().VirtualServices(cat.Namespace).Update(ctx, vs, metav1.UpdateOptions{})
	}

	return create || update, err
}

func (c *Controller) getUpdatedTenantVirtualServiceObject(ctx context.Context, cat *v1alpha1.CAPTenant, vs *istionwv1.VirtualService, cavName string, ca *v1alpha1.CAPApplication) (modified bool, err error) {
	if ca == nil {
		ca, err = c.getCachedCAPApplication(cat.Namespace, cat.Spec.CAPApplicationInstance)
		if err != nil {
			return modified, err
		}
	}

	// verify owner reference
	modified, err = c.enforceTenantResourceOwnership(&vs.ObjectMeta, &vs.TypeMeta, cat)
	if err != nil {
		return modified, err
	}

	routerPortInfo, err := c.getRouterServicePortInfo(cavName, ca.Namespace)
	if err != nil {
		return modified, err
	}

	spec := &networkingv1.VirtualService{
		Gateways: []string{},
		Hosts:    []string{cat.Spec.SubDomain + "." + ca.Spec.Domains.Primary},
		Http: []*networkingv1.HTTPRoute{{
			Match: []*networkingv1.HTTPMatchRequest{
				{Uri: &networkingv1.StringMatch{MatchType: &networkingv1.StringMatch_Prefix{Prefix: "/"}}},
			},
			Route: []*networkingv1.HTTPRouteDestination{{
				Destination: &networkingv1.Destination{
					Host: routerPortInfo.WorkloadName + ServiceSuffix + "." + cat.Namespace + ".svc.cluster.local",
					Port: &networkingv1.PortSelector{Number: uint32(routerPortInfo.Ports[0].Port)},
				},
				Weight: 100,
			}},
		}},
	}
	err = c.updateTenantVirtualServiceSpecWithSecondaryDomains(ctx, spec, cat, ca)
	if err != nil {
		return modified, err
	}

	// check whether changes have to be applied using hash comparison
	serializedSpec, err := json.Marshal(spec)
	if err != nil {
		return modified, fmt.Errorf("error serializing virtual service spec: %s", err.Error())
	}
	hash := sha256Sum(string(serializedSpec))
	if vs.Annotations[AnnotationResourceHash] != hash {
		vs.Spec = *spec
		updateResourceAnnotation(&vs.ObjectMeta, hash)
		modified = true
	}

	return modified, err
}

type OperatorGatewayMissingError struct{}

func (err *OperatorGatewayMissingError) Error() string {
	return "operator gateway for secondary domains missing"
}

func (c *Controller) updateTenantVirtualServiceSpecWithSecondaryDomains(ctx context.Context, spec *networkingv1.VirtualService, cat *v1alpha1.CAPTenant, ca *v1alpha1.CAPApplication) error {
	// Determine Ingress GW service for this app
	gwInfo, err := c.getIngressGatewayInfo(ctx, ca)
	if err != nil {
		return err
	}

	// Get the relevant central operator GW for this ingress GW
	operatorGW, _ := c.getOperatorGateway(ctx, gwInfo.Namespace, sha1Sum(gwInfo.DNSTarget))
	if operatorGW == nil {
		// requeue for later reconciliation
		return &OperatorGatewayMissingError{}
	}
	spec.Gateways = append(spec.Gateways, operatorGW.Namespace+"/"+operatorGW.Name)

	if len(ca.Spec.Domains.Secondary) == 0 {
		return nil
	}

	// add customer specific domains
	for _, domain := range ca.Spec.Domains.Secondary {
		spec.Hosts = append(spec.Hosts, cat.Spec.SubDomain+"."+domain)
	}

	return nil
}

func getIngressGatewayLabels(ca *v1alpha1.CAPApplication) map[string]string {
	ingressLabels := map[string]string{}
	for _, label := range ca.Spec.Domains.IstioIngressGatewayLabels {
		ingressLabels[label.Name] = label.Value
	}
	return ingressLabels
}

func (c *Controller) getIngressGatewayInfo(ctx context.Context, ca *v1alpha1.CAPApplication) (ingGwInfo *ingressGatewayInfo, err error) {
	// create ingress gateway selector from labels
	ingressLabelSelector, err := labels.ValidatedSelectorFromSet(getIngressGatewayLabels(ca))
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			c.Event(ca, nil, corev1.EventTypeWarning, CAPApplicationEventMissingIngressGatewayInfo, EventActionProcessingDomainResources, err.Error())
		}
	}()

	// Get relevant Ingress Gateway pods
	ingressPods, err := c.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: ingressLabelSelector.String()})
	if err != nil {
		return nil, err
	}

	// Determine relevant istio-ingressgateway namespace
	namespace := ""
	name := ""
	// Create a dummy lookup map for determining relevant pods
	relevantPodsNames := map[string]struct{}{}
	for _, pod := range ingressPods.Items {
		// We only support 1 ingress gateway pod namespace as of now! (Multiple pods e.g. replicas can exist in the same namespace)
		if namespace == "" {
			namespace = pod.Namespace
			name = pod.Name
		} else if namespace != pod.Namespace {
			return nil, fmt.Errorf("more than one matching ingress gateway pod namespaces found for %s %s.%s", v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
		}
		relevantPodsNames[pod.Name] = struct{}{}
	}
	if namespace == "" {
		return nil, fmt.Errorf("no matching ingress gateway pod found for %s %s.%s", v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
	}

	// Get dnsTarget
	// First try to use dnsTarget --> if it is set
	dnsTarget := ca.Spec.Domains.DnsTarget
	// Attempt to get dnsTarget from Env
	if dnsTarget == "" {
		dnsTarget = envDNSTarget()
	}
	// Finally attempt to get dnsTarget from Service via annotation(s)
	if dnsTarget == "" {
		ingressGWSvc, err := c.getIngressGatewayService(ctx, namespace, relevantPodsNames, v1alpha1.CAPApplicationKind, &ca.ObjectMeta)
		if err != nil {
			return nil, err
		}
		if ingressGWSvc != nil {
			dnsTarget = getDNSTarget(ingressGWSvc)
		}
	}
	// No DNS Target --> Error
	if dnsTarget == "" {
		return nil, fmt.Errorf("ingress gateway service not annotated with dns target name for %s %s.%s", v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
	}

	// Return ingress Gateway info (Namespace and DNS target)
	return &ingressGatewayInfo{Namespace: namespace, Name: name, DNSTarget: dnsTarget}, nil
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

func (c *Controller) getLoadBalancerSvcs(ctx context.Context, istioIngressGWNamespace string) ([]corev1.Service, error) {
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

func (c *Controller) getIngressGatewayService(ctx context.Context, istioIngressGWNamespace string, relevantPodNames map[string]struct{}, refKind string, refObjectMeta *metav1.ObjectMeta) (*corev1.Service, error) {
	loadBalancerSvcs, err := c.getLoadBalancerSvcs(ctx, istioIngressGWNamespace)
	if err != nil {
		return nil, err
	}
	// Get Relevant services that match the ingress gw pod via selectors
	var ingressGwSvc corev1.Service
	for _, svc := range loadBalancerSvcs {
		// Get all matching ingress GW pods in the ingress gw namespace via ingress gw service selectors
		matchedPods, err := c.kubeClient.CoreV1().Pods(istioIngressGWNamespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(svc.Spec.Selector).String()})
		if err != nil {
			return nil, err
		}
		for _, pod := range matchedPods.Items {
			if _, ok := relevantPodNames[pod.Name]; ok {
				if ingressGwSvc.Name == "" {
					// we only expect 1 ingress gateway service in the cluster
					ingressGwSvc = svc
					break
				} else if ingressGwSvc.Name != svc.Name {
					return nil, fmt.Errorf("more than one matching ingress gateway service found for %s %s.%s", refKind, refObjectMeta.Namespace, refObjectMeta.Name)
				}
			}
		}
	}

	if ingressGwSvc.Name == "" {
		return nil, fmt.Errorf("unable to find a matching ingress gateway service for %s %s.%s", refKind, refObjectMeta.Namespace, refObjectMeta.Name)
	}
	return &ingressGwSvc, nil
}

type operatorDomainInfo struct {
	Namespace         string
	Name              string
	ingressGWSelector map[string]string
	dnsTarget         string
	Domains           []string
}

// Operator Domains is a dummy resource that is referenced by a DNSTarget (in QueuedItem) to handle "secondary" domains across all relevant CAPApplications
// TODO: ignore duplicate reconciliation calls for same dnsTarget, Finalizers... and a whole lot more!
func (c *Controller) reconcileOperatorDomains(ctx context.Context, item QueueItem, attempts int) error {
	// Get Relevant Domain Infos
	relevantDomainInfos, err := c.getRelevantOperatorDomainInfo(ctx)
	if err != nil {
		return err
	}

	for dnsTargetSum, relevantDomainInfo := range relevantDomainInfos {
		// When no secondary domains exists --> Cleanup and return
		if len(relevantDomainInfo.Domains) == 0 {
			return c.cleanUpOperatorDomains(ctx, relevantDomainInfo, dnsTargetSum)
		}

		// Handle Operator Gateway
		gw, err := c.handleOperatorGateway(ctx, relevantDomainInfo, dnsTargetSum)
		if err != nil {
			return err
		}
		// Handle Operator Certificate
		return c.handleOperatorCertificate(ctx, gw.Name, relevantDomainInfo, dnsTargetSum)
	}
	return nil
}

func (c *Controller) getRelevantOperatorDomainInfo(ctx context.Context) (map[string]*operatorDomainInfo, error) {
	relevantDomainInfos := map[string]*operatorDomainInfo{}
	operatorDomainGWs, err := c.istioInformerFactory.Networking().V1().Gateways().Lister().Gateways(metav1.NamespaceAll).List(labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}))
	if err != nil {
		return nil, err
	}
	// Collect existing operator gateways (without Domains)
	for _, operatorDomainGW := range operatorDomainGWs {
		dnsTargetSum := operatorDomainGW.Labels[LabelRelevantDNSTarget]
		relevantDomainInfos[dnsTargetSum] = &operatorDomainInfo{
			Namespace:         operatorDomainGW.Namespace,
			Name:              operatorDomainGW.Name,
			ingressGWSelector: operatorDomainGW.Spec.Selector,
			Domains:           []string{},
		}
	}

	allCAs, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(metav1.NamespaceAll).List(labels.Everything())
	if err != nil {
		return nil, err
	}
	// Create & Update relevant operator gateways with domains
	for i := range allCAs {
		ca := allCAs[i]
		// Create / Update relevant operator domain info
		if gwInfo, err := c.getIngressGatewayInfo(ctx, ca); err == nil {
			dnsTarget := trimDNSTarget(gwInfo.DNSTarget)

			dnsTargetSum := sha1Sum(gwInfo.DNSTarget)
			domains := []string{ca.Spec.Domains.Primary}
			domains = append(domains, ca.Spec.Domains.Secondary...)

			if relevantDomainInfo, ok := relevantDomainInfos[dnsTargetSum]; ok {
				relevantDomainInfo.Domains = append(relevantDomainInfo.Domains, domains...)
				// Fill dnsTarget
				relevantDomainInfo.dnsTarget = dnsTarget
			} else {
				relevantDomainInfos[dnsTargetSum] = &operatorDomainInfo{
					Namespace:         gwInfo.Namespace,
					Name:              OperatorDomainNamePrefix,
					ingressGWSelector: getIngressGatewayLabels(ca),
					dnsTarget:         dnsTarget,
					Domains:           domains,
				}
			}
		} else {
			return nil, err
		}
	}

	return relevantDomainInfos, nil
}

func (c *Controller) getOperatorGateway(ctx context.Context, gwNamespace string, dnsTargetSum string) (*istionwv1.Gateway, error) {
	gwSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelRelevantDNSTarget:   dnsTargetSum,
		LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
	})
	if err != nil {
		return nil, err
	}
	gwList, err := c.istioInformerFactory.Networking().V1().Gateways().Lister().Gateways(gwNamespace).List(gwSelector)
	if err != nil {
		return nil, err
	}
	if len(gwList) == 0 {
		return nil, nil
	}
	return gwList[0], nil
}

func (c *Controller) handleOperatorGateway(ctx context.Context, relevantDomainInfo *operatorDomainInfo, dnsTargetSum string) (*istionwv1.Gateway, error) {
	gw, err := c.getOperatorGateway(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
	if err != nil {
		return nil, err
	}
	hash := sha256Sum(fmt.Sprintf("%v", relevantDomainInfo))
	// If no Gateway exists yet --> create one
	if gw == nil {
		gw = &istionwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: relevantDomainInfo.Name,
				Annotations: map[string]string{
					AnnotationResourceHash:    hash,
					AnnotationOwnerIdentifier: OperatorDomainLabel,
				},
				Labels: map[string]string{
					LabelRelevantDNSTarget:   dnsTargetSum,
					LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
				},
			},
			Spec: networkingv1.Gateway{
				Selector: relevantDomainInfo.ingressGWSelector,
			},
		}
		c.updateServerInfo(gw, relevantDomainInfo, relevantDomainInfo.dnsTarget)
		gw, err = c.istioClient.NetworkingV1().Gateways(relevantDomainInfo.Namespace).Create(ctx, gw, metav1.CreateOptions{})
	} else if gw.Annotations[AnnotationResourceHash] != hash { // Check if update is needed
		// Update the relevant gw parts, if there are changes (detected via sha256 sum)
		gw = gw.DeepCopy()
		c.updateServerInfo(gw, relevantDomainInfo, relevantDomainInfo.dnsTarget)
		// Update hash value on annotation
		updateResourceAnnotation(&gw.ObjectMeta, hash)
		// Trigger the actual update on the resource
		gw, err = c.istioClient.NetworkingV1().Gateways(relevantDomainInfo.Namespace).Update(ctx, gw, metav1.UpdateOptions{})
	}
	return gw, err
}

func (c *Controller) updateServerInfo(gw *istionwv1.Gateway, relevantDomainInfo *operatorDomainInfo, dnsTarget string) {
	gw.Spec.Servers = []*networkingv1.Server{}
	checkMap := map[string]struct{}{}
	for _, domain := range relevantDomainInfo.Domains {
		if _, ok := checkMap[domain]; ok {
			continue
		}
		gw.Spec.Servers = append(gw.Spec.Servers, getGatewayServerSpec(domain, dnsTarget))
		checkMap[domain] = struct{}{}
	}
}

func (c *Controller) handleOperatorCertificate(ctx context.Context, certName string, relevantDomainInfo *operatorDomainInfo, dnsTargetSum string) error {
	hash := sha256Sum(fmt.Sprintf("%v", relevantDomainInfo))
	dnsTarget := trimDNSTarget(relevantDomainInfo.dnsTarget)
	switch certificateManager() {
	case certManagerGardener:
		cert, err := c.getGardenerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
		if err != nil {
			return err
		}
		// If no certiicate exists yet --> create one
		if cert == nil {
			cert := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name: certName,
					Annotations: map[string]string{
						AnnotationResourceHash:    hash,
						AnnotationOwnerIdentifier: OperatorDomainLabel,
					},
					Labels: map[string]string{
						LabelRelevantDNSTarget:   dnsTargetSum,
						LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
					},
				},
				Spec: getGardenerCertificateSpec(dnsTarget, dnsTarget),
			}
			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
			_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(relevantDomainInfo.Namespace).Create(ctx, cert, metav1.CreateOptions{})
		} else if cert.Annotations[AnnotationResourceHash] != hash {
			// Update the relevant certificate parts, if there are changes (detected via sha256 sum)
			cert = cert.DeepCopy()
			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
			// Update hash value on annotation
			updateResourceAnnotation(&cert.ObjectMeta, hash)
			// Trigger the actual update on the resource
			_, err = c.gardenerCertificateClient.CertV1alpha1().Certificates(relevantDomainInfo.Namespace).Update(ctx, cert, metav1.UpdateOptions{})
		}
		return err
	case certManagerCertManagerIO:
		cert, err := c.getCertManagerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
		if err != nil {
			return err
		}
		// If no certiicate exists yet --> create one
		if cert == nil {
			cert := &certManagerv1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name: certName,
					Annotations: map[string]string{
						AnnotationResourceHash:    hash,
						AnnotationOwnerIdentifier: OperatorDomainLabel,
					},
					Labels: map[string]string{
						LabelRelevantDNSTarget:   dnsTargetSum,
						LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
					},
				},
				Spec: getCertManagerCertificateSpec("*."+dnsTarget, dnsTarget),
			}
			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
			_, err = c.certManagerCertificateClient.CertmanagerV1().Certificates(relevantDomainInfo.Namespace).Create(ctx, cert, metav1.CreateOptions{})
		} else if cert.Annotations[AnnotationResourceHash] != hash {
			// Update the relevant certificate parts, if there are changes (detected via sha256 sum)
			cert = cert.DeepCopy()
			cert.Spec.DNSNames = getCertificateDNSNames(relevantDomainInfo)
			// Update hash value on annotation
			updateResourceAnnotation(&cert.ObjectMeta, hash)
			// Trigger the actual update on the resource
			_, err = c.certManagerCertificateClient.CertmanagerV1().Certificates(relevantDomainInfo.Namespace).Update(ctx, cert, metav1.UpdateOptions{})
		}
		return err
	}
	return nil
}

func (c *Controller) getGardenerOperatorCertificate(ctx context.Context, gwNamespace string, dnsTargetSum string) (*certv1alpha1.Certificate, error) {
	certSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelRelevantDNSTarget:   dnsTargetSum,
		LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
	})
	if err != nil {
		return nil, err
	}

	certList, err := c.gardenerCertInformerFactory.Cert().V1alpha1().Certificates().Lister().Certificates(gwNamespace).List(certSelector)
	if err != nil {
		return nil, err
	}

	if len(certList) == 0 {
		return nil, nil
	}
	return certList[0], nil
}

func (c *Controller) getCertManagerOperatorCertificate(ctx context.Context, gwNamespace string, dnsTargetSum string) (*certManagerv1.Certificate, error) {
	certSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelRelevantDNSTarget:   dnsTargetSum,
		LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains),
	})
	if err != nil {
		return nil, err
	}

	certList, err := c.certManagerInformerFactory.Certmanager().V1().Certificates().Lister().Certificates(gwNamespace).List(certSelector)
	if err != nil {
		return nil, err
	}

	if len(certList) == 0 {
		return nil, nil
	}
	return certList[0], nil
}

func (c *Controller) cleanUpOperatorDomains(ctx context.Context, relevantDomainInfo *operatorDomainInfo, dnsTargetSum string) error {
	// Delete Operator Gateway (if any)
	gw, err := c.getOperatorGateway(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
	if err != nil {
		return err
	}
	if gw != nil {
		err := c.istioClient.NetworkingV1().Gateways(relevantDomainInfo.Namespace).Delete(ctx, gw.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	// Delete Operator certificate (if any)
	switch certificateManager() {
	case certManagerGardener:
		cert, err := c.getGardenerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
		if err != nil {
			return err
		}
		if cert != nil {
			return c.gardenerCertificateClient.CertV1alpha1().Certificates(relevantDomainInfo.Namespace).Delete(ctx, cert.Name, metav1.DeleteOptions{})
		}
	case certManagerCertManagerIO:
		cert, err := c.getCertManagerOperatorCertificate(ctx, relevantDomainInfo.Namespace, dnsTargetSum)
		if err != nil {
			return err
		}
		if cert != nil {
			return c.certManagerCertificateClient.CertmanagerV1().Certificates(relevantDomainInfo.Namespace).Delete(ctx, cert.Name, metav1.DeleteOptions{})
		}
	}
	return nil
}

func getCertificateDNSNames(relevantDomainInfo *operatorDomainInfo) []string {
	dnsNames := []string{}
	for _, domain := range relevantDomainInfo.Domains {
		// Don't add duplicate DNSNames when multiple apps provide same secondary domain!
		if !slices.ContainsFunc(dnsNames, func(dnsName string) bool { return dnsName == "*."+domain }) {
			dnsNames = append(dnsNames, "*."+domain)
		}
	}
	return dnsNames
}

func trimDNSTarget(dnsTarget string) string {
	// Trim dnsTarget to under 64 chars --> TODO: Also handle this in webhook/crd spec
	for len(dnsTarget) > 64 {
		dnsTarget = dnsTarget[strings.Index(dnsTarget, ".")+1:]
	}
	return sanitizeDNSTarget(dnsTarget)
}

func sanitizeDNSTarget(dnsTarget string) string {
	// Replace *.domain with x.domain as * is not a valid subdomain for a dns target
	return strings.ReplaceAll(dnsTarget, "*", "x")
}
