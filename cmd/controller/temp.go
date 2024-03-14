/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"strings"

	certManager "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	gardenerCert "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	gardenerDNS "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	istio "istio.io/client-go/pkg/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

type ownerInfo struct {
	kind           string
	ownerNamespace string
	ownerName      string
}

type appIdentifier struct {
	globalAccountId string
	appName         string
}

const (
	AnnotationOwnerIdentifier          = "sme.sap.com/owner-identifier"
	AnnotationBTPApplicationIdentifier = "sme.sap.com/btp-app-identifier"
	LabelOwnerIdentifierHash           = "sme.sap.com/owner-identifier-hash"
	LabelBTPApplicationIdentifierHash  = "sme.sap.com/btp-app-identifier-hash"
	CAPApplication                     = "CAPApplication"
	CAPApplicationVersion              = "CAPApplicationVersion"
	CAPTenant                          = "CAPTenant"
	CAPTenantOperation                 = "CAPTenantOperation"
	CAPOperator                        = "CAPOperator"
	OperatorDomains                    = "OperatorDomains"
)

var btpAppIdMap map[string]*appIdentifier
var ownerMap map[string]*ownerInfo

func checkHashedLabels(checkDone chan bool, client kubernetes.Interface, crdClient versioned.Interface, istioClient istio.Interface, gardenerCertificateClient gardenerCert.Interface, certManagerCertificateClient certManager.Interface, gardenerDNSClient gardenerDNS.Interface) {
	btpAppIdMap = map[string]*appIdentifier{}
	ownerMap = map[string]*ownerInfo{}
	// Always set the channel to true in the end
	defer func() {
		checkDone <- true
	}()

	ownerMap[CAPOperator+"."+OperatorDomains] = &ownerInfo{
		ownerNamespace: CAPOperator,
		ownerName:      OperatorDomains,
	}

	ctx := context.TODO()
	klog.InfoS("checking for old Labels on known resources")

	btpAppLabelReq, _ := labels.NewRequirement(AnnotationBTPApplicationIdentifier, selection.Exists, []string{})
	ownerLabelReq, _ := labels.NewRequirement(AnnotationOwnerIdentifier, selection.Exists, []string{})

	btpAppSelector := labels.NewSelector()
	btpAppSelector.Add(*btpAppLabelReq)

	ownerSelector := labels.NewSelector()
	ownerSelector.Add(*ownerLabelReq)

	btpAppOwnerSelector := labels.NewSelector()
	btpAppOwnerSelector.Add(*btpAppLabelReq, *ownerLabelReq)

	// CAP application with LabelBTPApplicationIdentifier
	caList, err := crdClient.SmeV1alpha1().CAPApplications("").List(ctx, metav1.ListOptions{LabelSelector: btpAppSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting CAPApplications", "selector", btpAppSelector.String())
		return
	}
	for _, ca := range caList.Items {
		// Update map with known good values
		btpAppIdMap[ca.Labels[AnnotationBTPApplicationIdentifier]] = &appIdentifier{
			globalAccountId: ca.Spec.GlobalAccountId,
			appName:         ca.Spec.BTPAppName,
		}
		ownerMap[ca.Namespace+"."+ca.Name] = &ownerInfo{
			ownerNamespace: ca.Namespace,
			ownerName:      ca.Name,
		}
		// certificates are created with CAPApplication as the kind in ownerinfo
		ownerMap[CAPApplication+"."+ca.Namespace+"."+ca.Name] = &ownerInfo{
			kind:           CAPApplication,
			ownerNamespace: ca.Namespace,
			ownerName:      ca.Name,
		}
		// add Label/Annotation for BTP App
		if updateLabelAnnotationMetadata(&ca.ObjectMeta, true, false) {
			crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).Update(ctx, &ca, metav1.UpdateOptions{})
		}
	}

	// CAP application version with LabelBTPApplicationIdentifier and LabelOwnerIdentifier
	cavList, err := crdClient.SmeV1alpha1().CAPApplicationVersions("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting CAPApplicationVersions", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, cav := range cavList.Items {
		ownerMap[cav.Namespace+"."+cav.Name] = &ownerInfo{
			ownerNamespace: cav.Namespace,
			ownerName:      cav.Name,
		}
		if updateLabelAnnotationMetadata(&cav.ObjectMeta, true, true) {
			crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).Update(ctx, &cav, metav1.UpdateOptions{})
		}
	}

	// CAP Tenant with LabelBTPApplicationIdentifier and LabelOwnerIdentifier
	catList, err := crdClient.SmeV1alpha1().CAPTenants("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting CAPTenants", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, cat := range catList.Items {
		ownerMap[cat.Namespace+"."+cat.Name] = &ownerInfo{
			ownerNamespace: cat.Namespace,
			ownerName:      cat.Name,
		}
		// DNS entries are being created with CAPTenant as the kind in owner info
		ownerMap[CAPTenant+"."+cat.Namespace+cat.Name] = &ownerInfo{
			kind:           CAPTenant,
			ownerNamespace: cat.Namespace,
			ownerName:      cat.Name,
		}
		if updateLabelAnnotationMetadata(&cat.ObjectMeta, true, true) {
			crdClient.SmeV1alpha1().CAPTenants(cat.Namespace).Update(ctx, &cat, metav1.UpdateOptions{})
		}
	}

	// CAP Tenant Operation with LabelOwnerIdentifier
	ctopList, err := crdClient.SmeV1alpha1().CAPTenantOperations("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting CAPTenantOperations", "selector", ownerSelector.String())
		return
	}
	for _, ctop := range ctopList.Items {
		ownerMap[ctop.Namespace+"."+ctop.Name] = &ownerInfo{
			ownerNamespace: ctop.Namespace,
			ownerName:      ctop.Name,
		}

		if updateLabelAnnotationMetadata(&ctop.ObjectMeta, false, true) {
			crdClient.SmeV1alpha1().CAPTenantOperations(ctop.Namespace).Update(ctx, &ctop, metav1.UpdateOptions{})
		}
	}

	// Cert Manager Certificates
	certManagerCertificateList, err := certManagerCertificateClient.CertmanagerV1().Certificates("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Certificates", "selector", ownerSelector.String())
		return
	}
	for _, cert := range certManagerCertificateList.Items {
		if updateLabelAnnotationMetadata(&cert.ObjectMeta, false, true) {
			certManagerCertificateClient.CertmanagerV1().Certificates(cert.Namespace).Update(ctx, &cert, metav1.UpdateOptions{})
		}
	}

	// Gardener Certificates
	gardenerCertificateList, err := gardenerCertificateClient.CertV1alpha1().Certificates("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Certificates", "selector", ownerSelector.String())
		return
	}
	for _, cert := range gardenerCertificateList.Items {
		if updateLabelAnnotationMetadata(&cert.ObjectMeta, false, true) {
			gardenerCertificateClient.CertV1alpha1().Certificates(cert.Namespace).Update(ctx, &cert, metav1.UpdateOptions{})
		}
	}

	// Gateways
	gwList, err := istioClient.NetworkingV1beta1().Gateways("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Gateways", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, gw := range gwList.Items {
		// Update one for just app id (primary domain gw)
		if updateLabelAnnotationMetadata(&gw.ObjectMeta, true, false) {
			istioClient.NetworkingV1beta1().Gateways(gw.Namespace).Update(ctx, gw, metav1.UpdateOptions{})
		}
		// Update one for just owner info (Secondary domain gw)
		if updateLabelAnnotationMetadata(&gw.ObjectMeta, false, true) {
			istioClient.NetworkingV1beta1().Gateways(gw.Namespace).Update(ctx, gw, metav1.UpdateOptions{})
		}
	}

	// DNS Entries
	dnsEntryList, err := gardenerDNSClient.DnsV1alpha1().DNSEntries("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting DNSEntries", "selector", ownerSelector.String())
		return
	}
	for _, dnsEntry := range dnsEntryList.Items {
		if updateLabelAnnotationMetadata(&dnsEntry.ObjectMeta, false, true) {
			gardenerDNSClient.DnsV1alpha1().DNSEntries(dnsEntry.Namespace).Update(ctx, &dnsEntry, metav1.UpdateOptions{})
		}
	}

	// Destination Rules
	destRuleList, err := istioClient.NetworkingV1beta1().DestinationRules("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting DestinationRules", "selector", ownerSelector.String())
		return
	}
	for _, destRule := range destRuleList.Items {
		if updateLabelAnnotationMetadata(&destRule.ObjectMeta, false, true) {
			istioClient.NetworkingV1beta1().DestinationRules(destRule.Namespace).Update(ctx, destRule, metav1.UpdateOptions{})
		}
	}

	// Virtual Services
	virtualServiceList, err := istioClient.NetworkingV1beta1().VirtualServices("").List(ctx, metav1.ListOptions{LabelSelector: ownerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting VirtualServices", "selector", ownerSelector.String())
		return
	}
	for _, virtualService := range virtualServiceList.Items {
		if updateLabelAnnotationMetadata(&virtualService.ObjectMeta, false, true) {
			istioClient.NetworkingV1beta1().VirtualServices(virtualService.Namespace).Update(ctx, virtualService, metav1.UpdateOptions{})
		}
	}

	// CAV Deployments
	deploymentList, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Deployments", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, deployment := range deploymentList.Items {
		if updateLabelAnnotationMetadata(&deployment.ObjectMeta, true, true) {
			client.AppsV1().Deployments(deployment.Namespace).Update(ctx, &deployment, metav1.UpdateOptions{})
		}
	}

	// CAV Services
	serviceList, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Services", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, service := range serviceList.Items {
		if updateLabelAnnotationMetadata(&service.ObjectMeta, true, true) {
			client.CoreV1().Services(service.Namespace).Update(ctx, &service, metav1.UpdateOptions{})
		}
	}

	// CTOP Jobs
	jobList, err := client.BatchV1().Jobs("").List(ctx, metav1.ListOptions{LabelSelector: btpAppOwnerSelector.String()})
	if err != nil {
		klog.ErrorS(err, "error getting Jobs", "selector", btpAppOwnerSelector.String())
		return
	}
	for _, job := range jobList.Items {
		if updateLabelAnnotationMetadata(&job.ObjectMeta, true, true) {
			client.BatchV1().Jobs(job.Namespace).Update(ctx, &job, metav1.UpdateOptions{})
		}
	}
}

func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}

func amendObjectMetadata(object *metav1.ObjectMeta, annotatedOldLabel string, hashLabel string, oldValue string, hashedValue string) (updated bool) {
	// Check if old label exists, if so remove it
	if _, ok := object.Labels[annotatedOldLabel]; ok {
		delete(object.Labels, annotatedOldLabel)
		klog.InfoS("Removed old label", "label", annotatedOldLabel, "label value", oldValue, "namespace", object.Namespace, "resource name", object.Name)
		updated = true
	}
	// Add hashed label as the new label with the hashed identifier value
	if _, ok := object.Labels[hashLabel]; !ok {
		object.Labels[hashLabel] = hashedValue
		klog.InfoS("Added hashed label", "label", hashLabel, "label value", hashedValue, "namespace", object.Namespace, "resource name", object.Name)
		updated = true
	}
	// Add old label as an annotation with the old value
	if _, ok := object.Annotations[annotatedOldLabel]; !ok {
		object.Annotations[annotatedOldLabel] = oldValue
		klog.InfoS("Added annotation", "annotation", annotatedOldLabel, "annotation value", oldValue, "namespace", object.Namespace, "resource name", object.Name)
		updated = true
	}
	// return if something was updated
	return updated
}

func updateLabelAnnotationMetadata(object *metav1.ObjectMeta, updateAppId bool, updateOwner bool) (updated bool) {
	if object.Labels == nil {
		object.Labels = make(map[string]string)
	}
	if object.Annotations == nil {
		object.Annotations = map[string]string{}
	}

	// Update BTP Application Identifier
	if updateAppId {
		var appDetails *appIdentifier
		ok := false
		appID := object.Labels[AnnotationBTPApplicationIdentifier]
		if appID != "" {
			if appDetails, ok = btpAppIdMap[appID]; !ok {
				index := strings.Index(appID, ".")
				appDetails = &appIdentifier{
					globalAccountId: appID[:index],
					appName:         appID[index+1:],
				}
				btpAppIdMap[appID] = appDetails
			}

			if amendObjectMetadata(object, AnnotationBTPApplicationIdentifier, LabelBTPApplicationIdentifierHash, strings.Join([]string{appDetails.globalAccountId, appDetails.appName}, "."), sha1Sum(appDetails.globalAccountId, appDetails.appName)) {
				updated = true
			}
		}
	}

	// Update OwnerInfo if owner details exists
	if updateOwner {
		var ownerDetails *ownerInfo
		owner := []string{}

		ok := false
		ownerID := object.Labels[AnnotationOwnerIdentifier]
		if ownerID != "" {
			if ownerDetails, ok = ownerMap[ownerID]; !ok {
				kind := ""
				if strings.Index(ownerID, CAPApplication+".") == 0 {
					kind = CAPApplication
					ownerID = ownerID[15:]
				} else if strings.Index(ownerID, CAPTenant+".") == 0 {
					kind = CAPTenant
					ownerID = ownerID[10:]
				}
				index := strings.Index(ownerID, ".")
				ownerDetails = &ownerInfo{
					kind:           kind,
					ownerNamespace: ownerID[:index],
					ownerName:      ownerID[index+1:],
				}
				ownerMap[ownerID] = ownerDetails
			}
			if ownerDetails.kind != "" {
				owner = append(owner, ownerDetails.kind)
			}
			owner = append(owner, ownerDetails.ownerNamespace, ownerDetails.ownerName)

			if amendObjectMetadata(object, AnnotationOwnerIdentifier, LabelOwnerIdentifierHash, strings.Join(owner, "."), sha1Sum(owner...)) {
				updated = true
			}
		}
	}

	return updated
}
