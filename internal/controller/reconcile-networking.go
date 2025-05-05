/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"google.golang.org/protobuf/types/known/durationpb"
	networkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const PrimaryDnsSuffix = "primary-dns"

const (
	CAPOperator                                  = "CAPOperator" // TO be removed after redoing unit tests
	EventActionReconcileServiceNetworking        = "ReconcileServiceNetworking"
	EventServiceNetworkingModified               = "ServiceNetworkingModified"
	EventServiceVirtualServiceModificationFailed = "ServiceVirtualServiceModificationFailed"
)

var (
	cNameLookup = int64(30)
	ttl         = int64(600)
)

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
	err = c.updateVirtualServiceSpecFromDomainReferences(ctx, spec, cat.Spec.SubDomain, ca)
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

func (c *Controller) updateVirtualServiceSpecFromDomainReferences(ctx context.Context, spec *networkingv1.VirtualService, subdomain string, ca *v1alpha1.CAPApplication) error {
	doms, cdoms, err := fetchDomainResourcesFromCache(ctx, c, ca.Spec.DomainRefs, ca.Namespace)
	if err != nil {
		return err
	}

	hosts := []string{}
	hosts = append(hosts, getDomainHosts(doms, subdomain)...)
	hosts = append(hosts, getDomainHosts(cdoms, subdomain)...)
	spec.Hosts = hosts

	gateways := []string{}
	gateways = append(gateways, getDomainGatewayReferences(doms)...)
	gateways = append(gateways, getDomainGatewayReferences(cdoms)...)
	spec.Gateways = gateways

	return nil
}

func (c *Controller) reconcileServiceNetworking(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) (requeue *ReconcileResult, err error) {
	var (
		reason, message string
		vsModified      bool
		eventType       string = corev1.EventTypeNormal
	)

	defer func() {
		if err != nil {
			eventType = corev1.EventTypeWarning
			message = err.Error()
		}
		if reason != "" { // raise event only when there is a modification or problem
			c.Event(cav, nil, eventType, reason, EventActionReconcileServiceNetworking, message)
		}
	}()

	if vsModified, err = c.reconcileServiceVirtualServices(ctx, cav, ca); err != nil {
		util.LogError(err, "Virtual service reconciliation failed", string(Processing), cav, nil, "version", cav.Spec.Version)
		reason = EventServiceVirtualServiceModificationFailed
		return
	}
	// update event reason
	if vsModified {
		message = fmt.Sprintf("VirtualService(s) for application %s.%s reconciled", cav.Namespace, cav.Name)
		reason = EventServiceNetworkingModified
	}

	return
}

func (c *Controller) reconcileServiceVirtualServices(ctx context.Context, cav *v1alpha1.CAPApplicationVersion, ca *v1alpha1.CAPApplication) (modified bool, err error) {
	ownerHash := sha1Sum(v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
	labelSelector := labels.SelectorFromSet(map[string]string{LabelOwnerIdentifierHash: ownerHash}).String()

	vsList, err := c.istioClient.NetworkingV1().VirtualServices(ca.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return
	}

	ownerRef := *metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind))
	aFoundIndex := []int{}

	for _, serviceExposure := range cav.Spec.ServiceExposures {
		var iIndex int
		iIndex, modified, err = c.modifyServiceExposure(ctx, vsList, serviceExposure, ca, cav, ownerHash, ownerRef)
		if err != nil {
			return
		}
		if iIndex > -1 {
			aFoundIndex = append(aFoundIndex, iIndex)
		}
	}

	// Delete VirtualServices that are not in the ServiceExposures list (TODO: may have to be done differently for service usage in multi-tenant scenarios)
	for i, vs := range vsList.Items {
		if !slices.Contains(aFoundIndex, i) {
			util.LogInfo("Deleting virtual service", string(Processing), ca, vs, "version", cav.Spec.Version)
			err = c.istioClient.NetworkingV1().VirtualServices(ca.Namespace).Delete(ctx, vs.Name, metav1.DeleteOptions{})
			if err != nil {
				return
			}
			modified = true
		}
	}
	return modified, err
}

func (c *Controller) modifyServiceExposure(ctx context.Context, vsList *istionwv1.VirtualServiceList, serviceExposure v1alpha1.ServiceExposure, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, ownerHash string, ownerRef metav1.OwnerReference) (iIndex int, modified bool, err error) {
	var (
		create, update bool
		vs             *istionwv1.VirtualService
	)

	if iIndex = slices.IndexFunc(vsList.Items, func(vs *istionwv1.VirtualService) bool {
		initialHost := vs.Spec.Hosts[0]
		vsSubDomain := strings.Split(initialHost, ".")[0]
		return serviceExposure.SubDomain == vsSubDomain
	}); iIndex == -1 {
		// VirtualService needs to be created
		vs = &istionwv1.VirtualService{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: ca.Name, // Generate a unique name based on app name
				Namespace:    ca.Namespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash: ownerHash,
				},
				OwnerReferences: []metav1.OwnerReference{ownerRef},
			},
		}
		create = true
	} else {
		// VirtualService already exists
		vs = vsList.Items[iIndex]
	}

	// update VirtualService Spec
	if update, err = c.getUpdatedServiceVirtualServiceObject(ctx, vs, serviceExposure, ownerRef, ca, cav.Name); err != nil {
		return
	}

	if create {
		util.LogInfo("Creating virtual service", string(Processing), ca, vs, "exposureSubDomain", serviceExposure.SubDomain, "version", cav.Spec.Version)
		_, err = c.istioClient.NetworkingV1().VirtualServices(ca.Namespace).Create(ctx, vs, metav1.CreateOptions{})
	} else if update {
		util.LogInfo("Updating virtual service", string(Processing), ca, vs, "exposureSubDomain", serviceExposure.SubDomain, "version", cav.Spec.Version)
		_, err = c.istioClient.NetworkingV1().VirtualServices(ca.Namespace).Update(ctx, vs, metav1.UpdateOptions{})
	}

	modified = create || update
	return
}

func (c *Controller) getUpdatedServiceVirtualServiceObject(ctx context.Context, vs *istionwv1.VirtualService, serviceExposure v1alpha1.ServiceExposure, ownerRef metav1.OwnerReference, ca *v1alpha1.CAPApplication, cavName string) (modified bool, err error) {
	// update owner reference
	if owner, ok := getOwnerByKind(vs.OwnerReferences, v1alpha1.CAPApplicationKind); !ok {
		vs.OwnerReferences = append(vs.OwnerReferences, ownerRef)
		modified = true
	} else if owner.Name != ca.Name {
		return false, fmt.Errorf("invalid owner reference found for %s %s.%s", vs.Kind, vs.Namespace, vs.Name)
	}

	httpRoutes := []*networkingv1.HTTPRoute{}
	for _, route := range serviceExposure.Routes {
		prefix := route.Path
		if route.Path == "" {
			prefix = "/"
		}
		httpRoutes = append(httpRoutes, &networkingv1.HTTPRoute{
			Match: []*networkingv1.HTTPMatchRequest{
				{Uri: &networkingv1.StringMatch{MatchType: &networkingv1.StringMatch_Prefix{Prefix: prefix}}},
			},
			Route: []*networkingv1.HTTPRouteDestination{{
				Destination: &networkingv1.Destination{
					Host: getWorkloadName(cavName, route.WorkloadName) + ServiceSuffix + "." + ca.Namespace + ".svc.cluster.local",
					Port: &networkingv1.PortSelector{Number: uint32(route.Port)},
				},
			}},
		})
	}

	spec := &networkingv1.VirtualService{
		Http: httpRoutes,
	}
	err = c.updateVirtualServiceSpecFromDomainReferences(ctx, spec, serviceExposure.SubDomain, ca)
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

func getIngressGatewayLabels(ca *v1alpha1.CAPApplication) map[string]string {
	ingressLabels := map[string]string{}
	for _, label := range ca.Spec.Domains.IstioIngressGatewayLabels {
		ingressLabels[label.Name] = label.Value
	}
	return ingressLabels
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

func trimDNSTarget(dnsTarget string) string {
	// Trim dnsTarget to under 62 chars (*. is added for cert CN) --> TODO: Also handle this in webhook/crd spec
	for len(dnsTarget) > 62 {
		dnsTarget = dnsTarget[strings.Index(dnsTarget, ".")+1:]
	}
	return dnsTarget
}

func sanitizeDNSTarget(dnsTarget string) string {
	// Replace *.domain with x.domain as * is not a valid subdomain for a dns target
	return strings.ReplaceAll(dnsTarget, "*", "x")
}
