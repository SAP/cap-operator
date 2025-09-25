/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	LabelSubscriptionGUID               = "sme.sap.com/subscription-guid"
	LabelTenantType                     = "sme.sap.com/tenant-type"
	OutdatedLabel                       = "sme.sap.com/subscription-guid-hash"
	AnnotationSubscriptionContextSecret = "sme.sap.com/subscription-context-secret"
)

func checkGUID(checkDone chan bool, client kubernetes.Interface, crdClient versioned.Interface) {
	// Always set the channel to true in the end
	defer func() {
		checkDone <- true
	}()

	guidDoesNotExist, _ := labels.NewRequirement(LabelSubscriptionGUID, selection.DoesNotExist, nil)
	nonProviderTenants, _ := labels.NewRequirement(LabelTenantType, selection.NotEquals, []string{"provider"}) //ignore provider tenants
	tenantsWithoutGuidSelector := labels.NewSelector().Add(*guidDoesNotExist, *nonProviderTenants)

	// Get all tenants in all namespaces
	tenants, err := crdClient.SmeV1alpha1().CAPTenants(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: tenantsWithoutGuidSelector.String()})
	if err != nil {
		return
	}

	klog.InfoS("Checking tenants for missing subscriptionGUID label", "relevant tenants", len(tenants.Items))

	for _, tenant := range tenants.Items {
		// Check if the label is already set, if so skip this tenant --> should never happen based on the label selector
		if _, ok := tenant.Labels[LabelSubscriptionGUID]; ok {
			klog.ErrorS(errors.New("Tenant with existing guid found"), "Skipping this tenant", "tenant", tenant.Namespace+"/"+tenant.Name, "tenantId", tenant.Spec.TenantId)
			continue
		}

		// If not, check if the subscriptionGUID annotation is present
		if subscriptionGUID, ok := tenant.Annotations[LabelSubscriptionGUID]; ok {
			klog.InfoS("Found tenant with subscriptionGUID annotation, updating to label", "tenant", tenant.Namespace+"/"+tenant.Name, "tenantId", tenant.Spec.TenantId)
			updateTenant(crdClient, &tenant, subscriptionGUID)
			continue
		}

		// Else --> we need to now look up the secret and fetch the Guid from there (if present)
		if subscriptionGUID := getSubscriptionGuidFromSecret(client, tenant.Namespace, tenant.Annotations[AnnotationSubscriptionContextSecret]); subscriptionGUID != "" {
			klog.InfoS("Found tenant with subscriptionGUID in secret, updating to label", "tenant", tenant.Namespace+"/"+tenant.Name, "secret", tenant.Annotations[AnnotationSubscriptionContextSecret], "tenantId", tenant.Spec.TenantId)
			updateTenant(crdClient, &tenant, subscriptionGUID)
		} else {
			// Else --> we cannot do anything, the tenant will remain without subscriptionGUID label
			klog.InfoS("Could not find subscriptionGUID for tenant, skipping", "tenant", tenant.Namespace+"/"+tenant.Name, "tenantId", tenant.Spec.TenantId)
		}
	}
}

func updateTenant(crdClient versioned.Interface, tenant *v1alpha1.CAPTenant, subscriptionGUID string) {
	tenant.Labels[LabelSubscriptionGUID] = subscriptionGUID
	// Delete outdated tenant label, if any
	delete(tenant.Labels, OutdatedLabel)
	// Delete the annotation with subscriptionGUI, if any
	delete(tenant.Annotations, LabelSubscriptionGUID)
	// Update the tenant with the new label (cleanup any outdated label)
	crdClient.SmeV1alpha1().CAPTenants(tenant.Namespace).Update(context.TODO(), tenant, metav1.UpdateOptions{})
	// Ignore errors during update --> we do not want to exit if one tenant update fails
}

func getSubscriptionGuidFromSecret(client kubernetes.Interface, namespace, secretName string) (subscriptionGUID string) {
	subscriptionGUID = ""
	secret, _ := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if secret == nil {
		// Secret may be missing for old tenants
		return
	}
	subscriptionPayload := map[string]any{}
	// Read the secret data, which is stored under "subscriptionContext", ignore errors
	json.Unmarshal(secret.Data["subscriptionContext"], &subscriptionPayload)

	subscriptionGuid, ok := subscriptionPayload["subscriptionGUID"]
	if !ok {
		// SubscriptionGUID may be missing for some tenants
		return
	}
	// This should be the right string at this point
	subscriptionGUID = subscriptionGuid.(string)
	return
}
