/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

type matchingDomainDetails struct {
	name string
	kind string
}

const (
	LabelMigratedToDomainRefsFromCA = "sme.sap.com/migrated-to-domain-refs-from-ca"
	PrimaryDomainSuffix             = "-primary"
	CAPOperatorDomainsPrefix        = "cap-operator-domains-"
)

var jsonpatchType = admissionv1.PatchTypeJSONPatch

func (wh *WebhookHandler) Mutate(w http.ResponseWriter, r *http.Request) {
	// read incoming request to bytes
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %w", AdmissionError, err))
		return
	}

	// create admission review from bytes
	admissionReview := getAdmissionRequestFromBytes(w, body)
	if admissionReview == nil {
		return
	}
	admissionReview.Response = &admissionv1.AdmissionResponse{
		UID: admissionReview.Request.UID,
	}

	klog.InfoS("incoming admission review (mutate)", "kind", admissionReview.Request.Kind.Kind)

	switch admissionReview.Request.Kind.Kind {
	case v1alpha1.CAPApplicationKind:
		err = wh.mutateCA(admissionReview)
	}

	if err != nil {
		klog.ErrorS(err, "error in admission review (mutate)", "kind", admissionReview.Request.Kind.Kind, "name", admissionReview.Request.Name, "namespace", admissionReview.Request.Namespace)
		admissionReview.Response.Result = &metav1.Status{
			Message: err.Error(),
		}
	} else {
		admissionReview.Response.Allowed = true
	}

	// prepare response
	if bytes, err := json.Marshal(&admissionReview); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %w", AdmissionError, err))
	} else {
		w.Write(bytes)
	}
}

func (wh *WebhookHandler) mutateCA(admissionReview *admissionv1.AdmissionReview) error {
	caObjOld := v1alpha1.CAPApplication{}
	caObj := v1alpha1.CAPApplication{}

	// Note: OldObject is nil for "CONNECT" and "CREATE" operations
	if admissionReview.Request.Operation == admissionv1.Delete || admissionReview.Request.Operation == admissionv1.Update {
		if _, _, err := universalDeserializer.Decode(admissionReview.Request.OldObject.Raw, nil, &caObjOld); err != nil {
			return err
		}
	}
	if admissionReview.Request.Operation == admissionv1.Update || admissionReview.Request.Operation == admissionv1.Create {
		// Note: Object is nil for "DELETE" operation
		if _, _, err := universalDeserializer.Decode(admissionReview.Request.Object.Raw, nil, &caObj); err != nil {
			return err
		}

		// If there is no domains, we skip the migration
		if !(caObj.Spec.Domains.Primary != "" || len(caObj.Spec.Domains.Secondary) > 0) {
			return nil
		}
		// Domains are DEPRECATED --> migrate to domainRefs
		admissionReview.Response.Warnings = append(admissionReview.Response.Warnings, "CAPApplication --> Spec.Domains is deprecated, use Spec.DomainRefs instead")
		// Check if we can migrate
		canMigrate, err := wh.canMigrate(&caObj)
		if err != nil {
			return err
		}
		if canMigrate {
			admissionReview.Response.Warnings = append(admissionReview.Response.Warnings, "Automatically migrating Domains to DomainRefs for CAPApplication: "+caObj.Namespace+"/"+caObj.Name)
			klog.InfoS("migrating domains to domainRefs", "primary", caObj.Spec.Domains.Primary, "secondary", caObj.Spec.Domains.Secondary)
			return wh.migrateDomainsToDomainRefs(&caObj, admissionReview)
		}
	}
	return nil
}

func (wh *WebhookHandler) canMigrate(ca *v1alpha1.CAPApplication) (bool, error) {
	// Check if the Domains field is not empty
	caExisting, err := wh.CrdClient.SmeV1alpha1().CAPApplications(ca.Namespace).Get(context.TODO(), ca.Name, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return false, err
	}

	if caExisting != nil && len(caExisting.Spec.DomainRefs) > 0 {
		return false, nil
	}
	// At this point, either the CAPApplication does not exist -or- it does not have any domainRefs, so we can proceed with migration
	return true, nil
}

func (wh *WebhookHandler) migrateDomainsToDomainRefs(ca *v1alpha1.CAPApplication, admissionReview *admissionv1.AdmissionReview) error {
	// Create a new CAPApplication object based on the old object, so that we can add domainRefs and remove the old Domains field
	caMigrated := ca.DeepCopy()

	// Initialize DomainRefs if nil or non-empty to an empty slice
	if caMigrated.Spec.DomainRefs == nil || len(caMigrated.Spec.DomainRefs) > 0 {
		caMigrated.Spec.DomainRefs = []v1alpha1.DomainRef{}
	}

	// Migrate Primary Domain to DomainRefs
	if ca.Spec.Domains.Primary != "" {
		err := wh.handleDomain(ca.Spec.Domains.Primary, caMigrated, -1)
		if err != nil {
			return err
		}
	}

	// Migrate Secondary Domains to DomainRefs
	if len(ca.Spec.Domains.Secondary) > 0 {
		for index, secondaryDomain := range ca.Spec.Domains.Secondary {
			err := wh.handleDomain(secondaryDomain, caMigrated, index)
			if err != nil {
				return err
			}
		}
	}

	// Remove the old Domains field, once migrated
	// Note: This is done to ensure that the old Domains field is not present in the migrated object
	caMigrated.Spec.Domains = v1alpha1.ApplicationDomains{}

	// Get JSON representation of current and migrated CAPApplication object(s)
	caRaw, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	caMigratedRaw, err := json.Marshal(caMigrated)
	if err != nil {
		return err
	}

	// Create JSON patch to update the CAPApplication object based on migrated object
	patch, err := jsonpatch.CreatePatch(caRaw, caMigratedRaw)
	if err != nil {
		return err
	}

	// Create the admission response with the patch
	jsonp, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	// Set the response with JSONPatch in the admission review
	admissionReview.Response.Patch = jsonp
	admissionReview.Response.PatchType = &jsonpatchType

	return nil
}

func (wh *WebhookHandler) handleDomain(domain string, ca *v1alpha1.CAPApplication, index int) error {
	// Check if the domain already exists in the current namespace or as a ClusterDomain
	domainDetails, err := wh.getDomain(domain, ca.Namespace)
	if err != nil {
		return err
	}
	if domainDetails == nil {
		klog.InfoS("No existing Domain resources found for domain", "domain", domain)
		annotations := map[string]string{
			LabelMigratedToDomainRefsFromCA: ca.Namespace + "/" + ca.Name,
		}
		ingressLabels := map[string]string{}
		for _, label := range ca.Spec.Domains.IstioIngressGatewayLabels {
			ingressLabels[label.Name] = label.Value
		}
		// If no matching domain is found, create a new one based on the index
		if index == -1 {
			domainDetails, err = wh.createDomain(domain, ca.Name+PrimaryDomainSuffix, ca.Namespace, annotations, ingressLabels)
		} else {
			domainDetails, err = wh.createClusterDomain(domain, CAPOperatorDomainsPrefix, annotations, ingressLabels)
		}
	}
	if err != nil {
		return err
	}

	ca.Spec.DomainRefs = append(ca.Spec.DomainRefs, v1alpha1.DomainRef{
		Name: domainDetails.name,
		Kind: domainDetails.kind,
	})

	klog.InfoS("DomainRef added to CAPApplication", "domainRef", domainDetails.name, "kind", domainDetails.kind)

	return nil
}

func (wh *WebhookHandler) getDomain(domain, namespace string) (*matchingDomainDetails, error) {
	// Check if the domain exists in current namespace
	doms, err := wh.CrdClient.SmeV1alpha1().Domains(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, dom := range doms.Items {
		if dom.Spec.Domain == domain {
			klog.InfoS("Existing Domain resource found for domain", "domain", domain)
			return &matchingDomainDetails{name: dom.Name, kind: v1alpha1.DomainKind}, nil
		}
	}
	// Else, check if a ClusterDomain exists with the same domain
	clusterDoms, err := wh.CrdClient.SmeV1alpha1().ClusterDomains(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, clusterDom := range clusterDoms.Items {
		if clusterDom.Spec.Domain == domain {
			klog.InfoS("Existing ClusterDomain resource found for domain", "domain", domain)
			return &matchingDomainDetails{name: clusterDom.Name, kind: v1alpha1.ClusterDomainKind}, nil
		}
	}
	return nil, nil
}

func (wh *WebhookHandler) createDomain(domain string, name string, namespace string, annotations map[string]string, ingressSelector map[string]string) (details *matchingDomainDetails, err error) {
	var createdDom *v1alpha1.Domain
	domainResource := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: v1alpha1.DomainSpec{
			Domain:          domain,
			IngressSelector: ingressSelector,
			TLSMode:         v1alpha1.TlsModeSimple,
			DNSMode:         v1alpha1.DnsModeWildcard,
		},
	}
	// Create the Domain in the Kubernetes cluster
	if createdDom, err = wh.CrdClient.SmeV1alpha1().Domains(namespace).Create(context.TODO(), domainResource, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	return &matchingDomainDetails{name: createdDom.Name, kind: v1alpha1.DomainKind}, nil
}

func (wh *WebhookHandler) createClusterDomain(domain string, name string, annotations map[string]string, ingressSelector map[string]string) (details *matchingDomainDetails, err error) {
	var createdDom *v1alpha1.ClusterDomain
	clusterDomainResource := &v1alpha1.ClusterDomain{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: name,
			Annotations:  annotations,
		},
		Spec: v1alpha1.DomainSpec{
			Domain:          domain,
			IngressSelector: ingressSelector,
			TLSMode:         v1alpha1.TlsModeSimple,
			DNSMode:         v1alpha1.DnsModeSubdomain,
		},
	}
	// Create the Domain in the Kubernetes cluster
	if createdDom, err = wh.CrdClient.SmeV1alpha1().ClusterDomains(metav1.NamespaceNone).Create(context.TODO(), clusterDomainResource, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	return &matchingDomainDetails{name: createdDom.Name, kind: v1alpha1.ClusterDomainKind}, nil
}
