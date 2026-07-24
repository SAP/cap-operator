/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (c *Controller) reconcileSubscription(ctx context.Context, item QueueItem, _ int) (result *ReconcileResult, err error) {
	cached, err := c.crdInformerFactory.Sme().V1alpha1().Subscriptions().Lister().Subscriptions(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	sub := cached.DeepCopy()

	defer func() {
		if statusErr := c.updateSubscriptionStatus(ctx, sub); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	// Handle deletion before any other work; defer must not be registered for this path.
	if sub.DeletionTimestamp != nil {
		return c.handleSubscriptionDeletion(ctx, sub)
	}

	// Ensure the finalizer is present; this may update the resource but reconcile continues in the same pass.
	if err = c.ensureSubscriptionFinalizer(ctx, sub); err != nil {
		return nil, err
	}

	// Ensure the subscription-guid label is set on the Subscription (used to correlate it with tenant operations)
	if sub.Labels[MetadataSubscriptionGUID] != sub.Spec.SubscriptionGuid {
		updated, updateErr := c.updateSubscriptionLabels(ctx, sub)
		if updateErr != nil {
			return nil, updateErr
		}
		*sub = *updated
	}

	// Identify the owning CAPApplication
	ca, err := c.getSubscriptionCAPApplication(sub)
	if err != nil {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateProcessingError, metav1.ConditionFalse, "ApplicationError", err.Error())
		return
	}

	// Start by ensuring the Subscription is in the Processing state before doing any work
	if sub.Status.State != v1alpha1.SubscriptionStateProcessing && sub.Status.State != v1alpha1.SubscriptionStateProcessingError {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateProcessing, metav1.ConditionFalse, "Processing", "Processing subscription")
		result = NewReconcileResultWithResource(ResourceSubscription, sub.Name, sub.Namespace, 0)
		tenant, _ := c.getOrCreateSubscriptionTenant(ctx, sub, ca)
		// In case of Subscription retry after an existing ProvisioningError, reconcile the existing CAPTenant resource too!
		if tenant != nil && tenant.Status.State == v1alpha1.CAPTenantStateProvisioningError {
			result.AddResource(ResourceCAPTenant, tenant.Name, tenant.Namespace, 0)
		}
		return
	}

	// Start processing the subscription
	return c.processSubscription(ctx, sub, ca)
}

func (c *Controller) processSubscription(ctx context.Context, sub *v1alpha1.Subscription, ca *v1alpha1.CAPApplication) (result *ReconcileResult, err error) {
	// Subscription specific URL handling
	// construct the tenant-specific subscription URL (including domain validation).
	appURL, err := c.getSubscriptionAppURL(sub, ca)
	if err != nil {
		util.LogError(err, "Error constructing subscription URL", string(Processing), sub, ca, "tenantId", sub.Spec.TenantId)
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateError, metav1.ConditionFalse, "URLError", "Error constructing subscription URL: "+err.Error())
		err = nil // Final state --> Do Not requeue the subscription due to processing errors (rate-limited error handling)
		return
	}
	sub.Status.Url = appURL

	// Identify (or create) the CAPTenant owned by this Subscription
	tenant, err := c.getOrCreateSubscriptionTenant(ctx, sub, ca)
	if err != nil {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateError, metav1.ConditionFalse, "TenantError", err.Error())
		return
	}

	// Wait for the owned tenant to become ready
	if !isCROConditionReady(tenant.Status.GenericStatus) {
		if tenant.Status.State == v1alpha1.CAPTenantStateProvisioningError || tenant.Status.State == v1alpha1.CAPTenantStateUpgradeError {
			err = fmt.Errorf("tenant %s.%s in state %s", tenant.Namespace, tenant.Name, tenant.Status.State)
			sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateError, metav1.ConditionFalse, "TenantError", err.Error())
			return
		}

		msg := fmt.Sprintf("waiting for tenant %s.%s to be ready", tenant.Namespace, tenant.Name)
		util.LogInfo("Waiting for tenant to be ready", string(Processing), sub, tenant, "tenantId", sub.Spec.TenantId)
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateProcessing, metav1.ConditionFalse, "TenantNotReady", msg)
		result = NewReconcileResultWithResource(ResourceSubscription, sub.Name, sub.Namespace, defaultResourceDelay)
		return
	}

	// Tenant is ready --> mark the Subscription ready
	sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateReady, metav1.ConditionTrue, "Ready", "Subscription is ready")
	return
}

// getOrCreateSubscriptionTenant identifies an existing CAPTenant for the subscription (via subscriptionGuid) or creates one owned by the Subscription.
func (c *Controller) getOrCreateSubscriptionTenant(ctx context.Context, sub *v1alpha1.Subscription, ca *v1alpha1.CAPApplication) (*v1alpha1.CAPTenant, error) {
	// First check if a tenant already exists for this subscription (identified by subscriptionGuid)
	tenant, err := c.getSubscriptionTenant(sub)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	// No tenant found; create one using the providerSubaccountId + btpAppName to identify the owning application (AppIdHash)
	return c.createSubscriptionTenant(ctx, sub, ca)
}

// getSubscriptionTenant looks up the CAPTenant for the subscription using the subscriptionGuid (and tenantId) labels.
func (c *Controller) getSubscriptionTenant(sub *v1alpha1.Subscription) (*v1alpha1.CAPTenant, error) {
	selector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelAppIdHash: sha1Sum(sub.Spec.ProviderSubaccountId, sub.Spec.AppName),
		LabelTenantId:  sub.Spec.TenantId,
	})
	if err != nil {
		return nil, err
	}

	tenants, err := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().CAPTenants(sub.Namespace).List(selector)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, nil
	}
	// Assume only one tenant matches the selector
	return tenants[0], nil
}

// createSubscriptionTenant creates a CAPTenant (owned by the Subscription) using the providerSubaccountId and btpAppName to derive the AppIdHash label/annotation.
func (c *Controller) createSubscriptionTenant(ctx context.Context, sub *v1alpha1.Subscription, ca *v1alpha1.CAPApplication) (*v1alpha1.CAPTenant, error) {
	appIdHash := sha1Sum(sub.Spec.ProviderSubaccountId, sub.Spec.AppName)

	util.LogInfo("Creating tenant for subscription", string(Processing), sub, nil, "tenantId", sub.Spec.TenantId, "subscriptionGuid", sub.Spec.SubscriptionGuid)

	tenant, err := c.crdClient.SmeV1alpha1().CAPTenants(sub.Namespace).Create(ctx, &v1alpha1.CAPTenant{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: sub.Name + "-",
			Namespace:    sub.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(sub, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.SubscriptionKind)),
				*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind)),
			},
			Annotations: map[string]string{
				AnnotationAppId:          fmt.Sprintf("%s.%s", sub.Spec.ProviderSubaccountId, sub.Spec.AppName),
				MetadataSubscriptionGUID: sub.Spec.SubscriptionGuid,
			},
			Labels: map[string]string{
				LabelAppIdHash:           appIdHash,
				LabelTenantId:            sub.Spec.TenantId,
				LabelTenantType:          TenantTypeConsumer,
				MetadataSubscriptionGUID: sub.Spec.SubscriptionGuid,
			},
		},
		Spec: v1alpha1.CAPTenantSpec{
			CAPApplicationInstance: ca.Name,
			BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
				TenantId:  sub.Spec.TenantId,
				SubDomain: sub.Spec.Subdomain,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		util.LogError(err, "Error creating tenant for subscription", string(Processing), sub, nil, "tenantId", sub.Spec.TenantId)
		return nil, err
	}

	util.LogInfo("Tenant created for subscription", string(Processing), sub, tenant, "tenantId", sub.Spec.TenantId)
	return tenant, nil
}

// updateSubscriptionLabels ensures the subscription-guid label is set on the Subscription resource itself
// (used to correlate it with the CAPTenant / CAPTenantOperation that carry the same label).
func (c *Controller) updateSubscriptionLabels(ctx context.Context, sub *v1alpha1.Subscription) (*v1alpha1.Subscription, error) {
	if sub.Labels == nil {
		sub.Labels = map[string]string{}
	}
	sub.Labels[MetadataSubscriptionGUID] = sub.Spec.SubscriptionGuid
	return c.crdClient.SmeV1alpha1().Subscriptions(sub.Namespace).Update(ctx, sub, metav1.UpdateOptions{})
}

func (c *Controller) updateSubscriptionStatus(ctx context.Context, sub *v1alpha1.Subscription) error {
	if isDeletionImminent(&sub.ObjectMeta) {
		return nil
	}
	updated, err := c.crdClient.SmeV1alpha1().Subscriptions(sub.Namespace).UpdateStatus(ctx, sub, metav1.UpdateOptions{})
	if updated != nil {
		*sub = *updated
	}
	return err
}

// ensureSubscriptionFinalizer adds the protection finalizer to the Subscription if not already present.
func (c *Controller) ensureSubscriptionFinalizer(ctx context.Context, sub *v1alpha1.Subscription) error {
	if sub.Finalizers == nil {
		sub.Finalizers = []string{}
	}
	if !addFinalizer(&sub.Finalizers, FinalizerSubscription) {
		return nil
	}
	_, err := c.crdClient.SmeV1alpha1().Subscriptions(sub.Namespace).Update(ctx, sub, metav1.UpdateOptions{})
	return err
}

// handleSubscriptionDeletion deletes the owned CAPTenant and removes the finalizer once the tenant is gone.
func (c *Controller) handleSubscriptionDeletion(ctx context.Context, sub *v1alpha1.Subscription) (*ReconcileResult, error) {
	tenant, err := c.getSubscriptionTenant(sub)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateDeleting, metav1.ConditionFalse, "Deleting", "Deleting subscription")
		if tenant.DeletionTimestamp == nil {
			util.LogInfo("Deleting CAPTenant for subscription", string(Deleting), sub, tenant, "tenantId", sub.Spec.TenantId)
			if err = c.crdClient.SmeV1alpha1().CAPTenants(sub.Namespace).Delete(ctx, tenant.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
		}
		return NewReconcileResultWithResource(ResourceSubscription, sub.Name, sub.Namespace, defaultResourceDelay), nil
	}
	// Tenant is gone; remove the finalizer so Kubernetes can complete the deletion.
	if removeFinalizer(&sub.Finalizers, FinalizerSubscription) {
		util.LogInfo("Removing finalizer from subscription after tenant deletion", string(Deleting), sub, nil, "tenantId", sub.Spec.TenantId)
		if _, err = c.crdClient.SmeV1alpha1().Subscriptions(sub.Namespace).Update(ctx, sub, metav1.UpdateOptions{}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// getSubscriptionCAPApplication identifies the owning CAPApplication for the subscription using the app identifier hash (derived from providerSubaccountId + btpAppName).
func (c *Controller) getSubscriptionCAPApplication(sub *v1alpha1.Subscription) (*v1alpha1.CAPApplication, error) {
	selector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelAppIdHash: sha1Sum(sub.Spec.ProviderSubaccountId, sub.Spec.AppName),
	})
	if err != nil {
		return nil, err
	}

	cas, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(sub.Namespace).List(selector)
	if err != nil {
		return nil, err
	}
	if len(cas) == 0 {
		return nil, fmt.Errorf("no CAPApplication found for subscription %s.%s", sub.Namespace, sub.Name)
	}
	// Assume only one application matches the selector
	return cas[0], nil
}

// getSubscriptionAppURL constructs the tenant-specific subscription URL for the Subscription,
// mirroring the subscription server's getAppURL logic (including domain validation).
func (c *Controller) getSubscriptionAppURL(sub *v1alpha1.Subscription, ca *v1alpha1.CAPApplication) (string, error) {
	needsValidation := true
	var subscriptionDomain string
	// Check if subscription domain is provided in the subscription spec (from the request payload).
	if sub.Spec.SubscriptionDomain != "" {
		subscriptionDomain = sub.Spec.SubscriptionDomain
		util.LogInfo("Using subscription domain from subscription spec", string(Processing), sub, ca, "subscriptionDomain", subscriptionDomain)
	} else {
		// Fallback:
		// First, check if subscription domain is provided in the CAPApplication annotation. If not, fallback to calculating the primary domain from the CAPApplication domain refs and use that as the subscription domain.
		subscriptionDomain = ca.Annotations[AnnotationSubscriptionDomain]
		if subscriptionDomain == "" {
			subscriptionDomain = c.getPrimarySubscriptionDomain(sub, ca)
			if subscriptionDomain == "" {
				return "", fmt.Errorf("no subscription domain found for application %s.%s", ca.Namespace, ca.Name)
			}
			needsValidation = false
			util.LogInfo("Using subscription domain from 'primary' calculation", string(Processing), sub, ca, "subscriptionDomain", subscriptionDomain)
		} else {
			util.LogInfo("Using subscription domain from CAPApplication annotation", string(Processing), sub, ca, "subscriptionDomain", subscriptionDomain)
		}
	}

	if needsValidation {
		if err := c.validateSubscriptionDomain(subscriptionDomain, ca.Namespace); err != nil {
			return "", err
		}
	}

	return "https://" + sub.Spec.Subdomain + "." + subscriptionDomain, nil
}

// validateSubscriptionDomain ensures the given domain is backed by a Domain (in the app's namespace) or a ClusterDomain.
func (c *Controller) validateSubscriptionDomain(domain, namespace string) error {
	// First check for Domains in the app's namespace
	domainsList, err := c.crdInformerFactory.Sme().V1alpha1().Domains().Lister().Domains(namespace).List(labels.Everything())
	if err != nil {
		return err
	}
	for _, d := range domainsList {
		if d.Spec.Domain == domain {
			return nil
		}
	}

	// Check for ClusterDomains if not found in the namespace
	clusterDomainsList, err := c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister().List(labels.Everything())
	if err != nil {
		return err
	}
	for _, cd := range clusterDomainsList {
		if cd.Spec.Domain == domain {
			return nil
		}
	}

	return fmt.Errorf("domain %s not found in Domains or ClusterDomains", domain)
}

// getPrimarySubscriptionDomain resolves the primary domain of the CAPApplication (first domain ref) to use as a fallback subscription domain.
func (c *Controller) getPrimarySubscriptionDomain(sub *v1alpha1.Subscription, ca *v1alpha1.CAPApplication) string {
	// If no domainRefs are specified, return an empty string
	if len(ca.Spec.DomainRefs) == 0 {
		return ""
	}
	// Use the first domain ref as the primary domain
	primaryDomainRef := ca.Spec.DomainRefs[0]
	domain := ""
	if primaryDomainRef.Kind == v1alpha1.DomainKind {
		primaryDom, err := c.crdInformerFactory.Sme().V1alpha1().Domains().Lister().Domains(ca.Namespace).Get(primaryDomainRef.Name)
		if err != nil {
			util.LogError(err, "Error getting primary domain", string(Processing), sub, ca, "domainRef", primaryDomainRef.Name)
		} else if primaryDom != nil {
			domain = primaryDom.Spec.Domain
		}
	} else {
		primaryDom, err := c.crdInformerFactory.Sme().V1alpha1().ClusterDomains().Lister().ClusterDomains(metav1.NamespaceAll).Get(primaryDomainRef.Name)
		if err != nil {
			util.LogError(err, "Error getting primary cluster domain", string(Processing), sub, ca, "domainRef", primaryDomainRef.Name)
		} else if primaryDom != nil {
			domain = primaryDom.Spec.Domain
		}
	}
	// Return the primary domain if it exists, else return an empty string
	return domain
}
