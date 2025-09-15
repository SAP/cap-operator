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

const (
	EventActionReconcileServiceNetworking        = "ReconcileServiceNetworking"
	EventServiceNetworkingModified               = "ServiceNetworkingModified"
	EventServiceVirtualServiceModificationFailed = "ServiceVirtualServiceModificationFailed"
)

const (
	serviceDNSSuffix                = ".svc.cluster.local"
	setCookie                       = "Set-Cookie"
	AnnotationLogoutEndpoint        = "sme.sap.com/logout-endpoint"
	AnnotationEnableSessionAffinity = "sme.sap.com/enable-session-affinity"
)

func (c *Controller) reconcileTenantNetworking(ctx context.Context, cat *v1alpha1.CAPTenant, cavName string, ca *v1alpha1.CAPApplication) (err error) {
	var (
		reason, message                           string
		drModified, vsModified, prevCavDrModified bool
		eventType                                 string = corev1.EventTypeNormal
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

	if drModified, err = c.reconcileTenantDestinationRule(ctx, cat, cat.Name, cavName); err != nil {
		util.LogError(err, "Destination rule reconciliation failed", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		reason = CAPTenantEventDestinationRuleModificationFailed
		return
	}

	// Enable session affinity
	if prevCavDrModified, err = c.reconcileTenantDestinationRuleForPrevCav(ctx, ca, cat); err != nil {
		util.LogError(err, "Destination rule reconciliation failed for previous cav", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		reason = CAPTenantEventDestinationRuleModificationFailed
		return
	}

	if vsModified, err = c.reconcileTenantVirtualService(ctx, cat, cavName, ca); err != nil {
		util.LogError(err, "Virtual service reconciliation failed", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		reason = CAPTenantEventVirtualServiceModificationFailed
		return
	}

	// update tenant status
	if drModified || vsModified || prevCavDrModified {
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

func (c *Controller) reconcileTenantDestinationRule(ctx context.Context, cat *v1alpha1.CAPTenant, drName string, cavName string) (modified bool, err error) {
	var (
		create, update bool
		dr             *istionwv1.DestinationRule
	)
	dr, err = c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).Get(ctx, drName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		dr = &istionwv1.DestinationRule{
			ObjectMeta: metav1.ObjectMeta{
				Name:            drName,
				Namespace:       cat.Namespace,
				Labels:          map[string]string{},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind))},
			},
		}
		create = true
	} else if err != nil {
		return
	}

	if update, err = c.getUpdatedTenantDestinationRuleObject(cat, dr, cavName); err != nil {
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

func (c *Controller) reconcileTenantDestinationRuleForPrevCav(ctx context.Context, ca *v1alpha1.CAPApplication, cat *v1alpha1.CAPTenant) (modified bool, err error) {
	if len(cat.Status.PreviousCAPApplicationVersions) == 0 {
		return false, nil
	}

	if ca.Annotations[AnnotationEnableSessionAffinity] == "true" {
		return c.handleSessionAffinityEnabled(ctx, cat)
	}

	return c.cleanupAllPreviousCavDRs(ctx, cat)
}

func (c *Controller) handleSessionAffinityEnabled(ctx context.Context, cat *v1alpha1.CAPTenant) (bool, error) {
	var modified bool
	var err error
	prevCav := cat.Status.PreviousCAPApplicationVersions[len(cat.Status.PreviousCAPApplicationVersions)-1]

	// Check if previous CAV exists
	_, cavGetErr := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(cat.Namespace).Get(prevCav)
	switch {
	case errors.IsNotFound(cavGetErr):
		// CAV doesn't exist, cleanup its DR
		modified, err = c.deleteDRIfExists(ctx, cat.Namespace, cat.Name+"-"+prevCav)
		if err != nil {
			return false, err
		}
	case cavGetErr != nil:
		// Some other error occurred while fetching CAV
		return false, cavGetErr
	default:
		// CAV exists, reconcile its DR
		modified, err = c.reconcileTenantDestinationRule(ctx, cat, cat.Name+"-"+prevCav, prevCav)
		if err != nil {
			return false, err
		}
	}

	// Clean up second-to-last CAV DR if it exists
	if len(cat.Status.PreviousCAPApplicationVersions) > 1 {
		secondLastCav := cat.Status.PreviousCAPApplicationVersions[len(cat.Status.PreviousCAPApplicationVersions)-2]
		drDeleted, err := c.deleteDRIfExists(ctx, cat.Namespace, cat.Name+"-"+secondLastCav)
		if err != nil {
			return false, err
		}
		modified = modified || drDeleted
	}

	return modified, nil
}

func (c *Controller) cleanupAllPreviousCavDRs(ctx context.Context, cat *v1alpha1.CAPTenant) (bool, error) {
	drNames := make(map[string]struct{})
	for _, cav := range cat.Status.PreviousCAPApplicationVersions {
		drNames[cat.Name+"-"+cav] = struct{}{}
	}

	drList, err := c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}

	var modified bool
	for _, dr := range drList.Items {
		if _, exists := drNames[dr.Name]; exists {
			if err := c.istioClient.NetworkingV1().DestinationRules(cat.Namespace).Delete(ctx, dr.Name, metav1.DeleteOptions{}); err != nil {
				return false, err
			}
			modified = true
		}
	}
	return modified, nil
}

func (c *Controller) deleteDRIfExists(ctx context.Context, namespace, drName string) (bool, error) {
	err := c.istioClient.NetworkingV1().DestinationRules(namespace).Delete(ctx, drName, metav1.DeleteOptions{})
	switch {
	case errors.IsNotFound(err):
		return false, nil // Nothing to delete
	case err != nil:
		return false, err // Unexpected error
	default:
		return true, nil // Deleted successfully
	}
}

func (c *Controller) getUpdatedTenantDestinationRuleObject(cat *v1alpha1.CAPTenant, dr *istionwv1.DestinationRule, cavName string) (modified bool, err error) {
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
		Host: routerPortInfo.WorkloadName + ServiceSuffix + "." + cat.Namespace + serviceDNSSuffix,
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
		dr.Spec = *spec.DeepCopy()
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

	if update, err = c.getUpdatedTenantVirtualServiceObject(cat, vs, cavName, ca); err != nil {
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

func (c *Controller) getUpdatedTenantVirtualServiceObject(cat *v1alpha1.CAPTenant, vs *istionwv1.VirtualService, cavName string, ca *v1alpha1.CAPApplication) (modified bool, err error) {
	// verify owner reference
	modified, err = c.enforceTenantResourceOwnership(&vs.ObjectMeta, &vs.TypeMeta, cat)
	if err != nil {
		return modified, err
	}

	headers, err := getNetworkingHeaders(ca)
	if err != nil {
		return modified, fmt.Errorf("error getting headers via CA annotations for %s %s.%s, error: %v", vs.Kind, vs.Namespace, vs.Name, err)
	}

	spec := &networkingv1.VirtualService{}
	// check if session affinity is enabled
	if ca.Annotations[AnnotationEnableSessionAffinity] == "true" {
		spec.Http, err = c.getVirtualServiceHttpRoutes(cat, cavName, headers)
		if err != nil {
			return modified, err
		}
	} else {
		routerPortInfo, err := c.getRouterServicePortInfo(cavName, ca.Namespace)
		if err != nil {
			return modified, err
		}
		spec.Http = []*networkingv1.HTTPRoute{{
			Match: []*networkingv1.HTTPMatchRequest{
				{Uri: &networkingv1.StringMatch{MatchType: &networkingv1.StringMatch_Prefix{Prefix: "/"}}},
			},
			Route: []*networkingv1.HTTPRouteDestination{{
				Destination: &networkingv1.Destination{
					Host: routerPortInfo.WorkloadName + ServiceSuffix + "." + cat.Namespace + serviceDNSSuffix,
					Port: &networkingv1.PortSelector{Number: uint32(routerPortInfo.Ports[0].Port)},
				},
				Weight:  100,
				Headers: headers,
			}},
		}}
	}

	err = c.updateVirtualServiceSpecFromDomainReferences(spec, cat.Spec.SubDomain, ca)
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
		vs.Spec = *spec.DeepCopy()
		updateResourceAnnotation(&vs.ObjectMeta, hash)
		modified = true
	}

	return modified, err
}

func (c *Controller) getVirtualServiceHttpRoutes(cat *v1alpha1.CAPTenant, currentCavName string, headers *networkingv1.Headers) ([]*networkingv1.HTTPRoute, error) {
	var (
		httpRoutes []*networkingv1.HTTPRoute
		prevCav    *v1alpha1.CAPApplicationVersion
		prevDest   *networkingv1.Destination
		err        error
	)

	// Lookup previous CAV (if any)
	if len(cat.Status.PreviousCAPApplicationVersions) > 0 {
		prevCavName := cat.Status.PreviousCAPApplicationVersions[len(cat.Status.PreviousCAPApplicationVersions)-1]
		prevCav, err = c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(cat.Namespace).Get(prevCavName)

		if err == nil { // only if found
			if prevDest, err = c.getVirtualServiceHttpRouteDestination(prevCavName, cat.Namespace); err != nil {
				return nil, err
			}
		} else if !errors.IsNotFound(err) {
			return nil, err
		}
	}

	// Lookup current CAV destination
	currentDest, err := c.getVirtualServiceHttpRouteDestination(currentCavName, cat.Namespace)
	if err != nil {
		return nil, err
	}

	// Retrieve current CAV for logout endpointannotations
	currentCav, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(cat.Namespace).Get(currentCavName)
	if err != nil {
		return nil, err
	}

	// --- Add routes ---
	// Logoff/logout routes
	if prevDest != nil {
		httpRoutes = append(httpRoutes, buildVirtualServiceLogOffHttpRoute(prevCav.Name, prevCav.Annotations[AnnotationLogoutEndpoint], prevDest, headers))
	}
	httpRoutes = append(httpRoutes, buildVirtualServiceLogOffHttpRoute(currentCavName, currentCav.Annotations[AnnotationLogoutEndpoint], currentDest, headers))

	// Cookie routes
	if prevDest != nil {
		httpRoutes = append(httpRoutes, buildVirtualServiceCookieHttpRoute(prevCav.Name, prevDest))
	}
	httpRoutes = append(httpRoutes, buildVirtualServiceCookieHttpRoute(currentCavName, currentDest))

	// Default route to current CAV
	httpRoutes = append(httpRoutes, buildVirtualServiceDefaultHttpRoute(currentCavName, currentDest, headers))

	return httpRoutes, nil
}

func (c *Controller) getVirtualServiceHttpRouteDestination(cavName string, namespace string) (*networkingv1.Destination, error) {
	CAVRouterPortInfo, err := c.getRouterServicePortInfo(cavName, namespace)
	if err != nil {
		return nil, err
	}

	return &networkingv1.Destination{
		Host: CAVRouterPortInfo.WorkloadName + ServiceSuffix + "." + namespace + ".svc.cluster.local",
		Port: &networkingv1.PortSelector{Number: uint32(CAVRouterPortInfo.Ports[0].Port)},
	}, nil
}

func buildVirtualServiceDefaultHttpRoute(cavName string, dest *networkingv1.Destination, headers *networkingv1.Headers) *networkingv1.HTTPRoute {
	return &networkingv1.HTTPRoute{
		Route: []*networkingv1.HTTPRouteDestination{{
			Destination: dest,
			Weight:      100,
		}},
		Headers: enhanceHeadersWithCookie(headers, sessionCookie(cavName), "add"),
	}
}

func buildVirtualServiceLogOffHttpRoute(cavName, logoutEndpoint string, dest *networkingv1.Destination, headers *networkingv1.Headers) *networkingv1.HTTPRoute {
	// Default logout/logoff regex
	uriRegex := "^|.*(logout|logoff).*"
	if logoutEndpoint != "" {
		uriRegex = "^|.*(" + logoutEndpoint + ").*"
	}

	return &networkingv1.HTTPRoute{
		Match: []*networkingv1.HTTPMatchRequest{{
			Headers: map[string]*networkingv1.StringMatch{
				"Cookie": {MatchType: &networkingv1.StringMatch_Regex{Regex: cookieRegex(cavName)}},
			},
			Uri: &networkingv1.StringMatch{
				MatchType: &networkingv1.StringMatch_Regex{Regex: uriRegex},
			},
		}},
		Route: []*networkingv1.HTTPRouteDestination{{
			Destination: dest,
			Weight:      100,
		}},
		Headers: enhanceHeadersWithCookie(headers, expiredCookie(cavName), "set"),
	}
}

func buildVirtualServiceCookieHttpRoute(cavName string, dest *networkingv1.Destination) *networkingv1.HTTPRoute {
	return &networkingv1.HTTPRoute{
		Match: []*networkingv1.HTTPMatchRequest{{
			Headers: map[string]*networkingv1.StringMatch{
				"Cookie": {MatchType: &networkingv1.StringMatch_Regex{Regex: cookieRegex(cavName)}},
			},
		}},
		Route: []*networkingv1.HTTPRouteDestination{{
			Destination: dest,
			Weight:      100,
		}},
	}
}

func enhanceHeadersWithCookie(headers *networkingv1.Headers, cookie string, op string) *networkingv1.Headers {
	if headers != nil && headers.Response != nil {
		h := headers.DeepCopy()
		if h.Response.Add == nil {
			h.Response.Add = map[string]string{}
		}
		if h.Response.Set == nil {
			h.Response.Set = map[string]string{}
		}
		switch op {
		case "add":
			h.Response.Add[setCookie] = cookie
		case "set":
			h.Response.Set[setCookie] = cookie
		}
		return h
	}

	if op == "add" {
		return &networkingv1.Headers{Response: &networkingv1.Headers_HeaderOperations{
			Add: map[string]string{setCookie: cookie},
		}}
	}
	return &networkingv1.Headers{Response: &networkingv1.Headers_HeaderOperations{
		Set: map[string]string{setCookie: cookie},
	}}
}

func cookieRegex(cavName string) string {
	return "(^|.*; )COP_CAV=" + cavName + "($|; .*)"
}

func sessionCookie(cavName string) string {
	return "COP_CAV=" + cavName + ";Path=/;HttpOnly;Secure"
}

func expiredCookie(cavName string) string {
	return "COP_CAV=" + cavName + ";Path=/;HttpOnly;Secure;Max-Age=0"
}

func (c *Controller) updateVirtualServiceSpecFromDomainReferences(spec *networkingv1.VirtualService, subdomain string, ca *v1alpha1.CAPApplication) error {
	doms, cdoms, err := fetchDomainResourcesFromCache(c, ca.Spec.DomainRefs, ca.Namespace)
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

func (c *Controller) reconcileServiceNetworking(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) (err error) {
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
			// collect service operation metrics only if there is an error or modification on VirtualService
			collectServiceOperationMetrics(cav, err)
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
	if update, err = c.getUpdatedServiceVirtualServiceObject(vs, serviceExposure, ownerRef, ca, cav.Name); err != nil {
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

func (c *Controller) getUpdatedServiceVirtualServiceObject(vs *istionwv1.VirtualService, serviceExposure v1alpha1.ServiceExposure, ownerRef metav1.OwnerReference, ca *v1alpha1.CAPApplication, cavName string) (modified bool, err error) {
	// update owner reference
	if owner, ok := getOwnerByKind(vs.OwnerReferences, v1alpha1.CAPApplicationKind); !ok {
		vs.OwnerReferences = append(vs.OwnerReferences, ownerRef)
		modified = true
	} else if owner.Name != ca.Name {
		return false, fmt.Errorf("invalid owner reference found for %s %s.%s", vs.Kind, vs.Namespace, vs.Name)
	}

	headers, err := getNetworkingHeaders(ca)
	if err != nil {
		return modified, fmt.Errorf("error getting headers via CA annotations for %s %s.%s, error: %v", vs.Kind, vs.Namespace, vs.Name, err)
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
					Host: getWorkloadName(cavName, route.WorkloadName) + ServiceSuffix + "." + ca.Namespace + serviceDNSSuffix,
					Port: &networkingv1.PortSelector{Number: uint32(route.Port)},
				},
				Headers: headers,
			}},
		})
	}

	spec := &networkingv1.VirtualService{
		Http: httpRoutes,
	}
	err = c.updateVirtualServiceSpecFromDomainReferences(spec, serviceExposure.SubDomain, ca)
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
		vs.Spec = *spec.DeepCopy()
		updateResourceAnnotation(&vs.ObjectMeta, hash)
		modified = true
	}

	return modified, err
}

func getNetworkingHeaders(ca *v1alpha1.CAPApplication) (nwHeaders *networkingv1.Headers, err error) {
	extractHeaders := func(annotation string) (headerOps *networkingv1.Headers_HeaderOperations, err error) {
		headers := map[string]string{}
		headersJson := ca.Annotations[annotation]
		if headersJson != "" {
			err = json.Unmarshal([]byte(headersJson), &headers)
			if err != nil {
				return headerOps, err
			}
			if len(headers) > 0 {
				headerOps = &networkingv1.Headers_HeaderOperations{
					Set: headers,
				}
			}
		}
		return headerOps, nil
	}
	// extract request headers from annotations
	reqHeaders, err := extractHeaders(AnnotationVSRouteRequestHeaderSet)
	if err != nil {
		return nwHeaders, err
	}
	// extract response headers from annotations
	resHeaders, err := extractHeaders(AnnotationVSRouteResponseHeaderSet)
	if err != nil {
		return nwHeaders, err
	}

	if reqHeaders != nil || resHeaders != nil {
		nwHeaders = &networkingv1.Headers{
			Request:  reqHeaders,
			Response: resHeaders,
		}
	}

	return nwHeaders, err
}
