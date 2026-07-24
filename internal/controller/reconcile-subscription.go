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

	// Ensure the subscription-guid label is set on the Subscription (used to correlate it with tenant operations)
	if sub.Labels[MetadataSubscriptionGUID] != sub.Spec.SubscriptionGuid {
		updated, updateErr := c.updateSubscriptionLabels(ctx, sub)
		if updateErr != nil {
			return nil, updateErr
		}
		*sub = *updated
	}

	// Start by ensuring the Subscription is in the Processing state before doing any work
	if sub.Status.State != v1alpha1.SubscriptionStateProcessing {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateProcessing, metav1.ConditionFalse, "Processing", "Processing subscription")
		sub.SetStatusCondition(string(v1alpha1.ConditionTypeTenantReady), metav1.ConditionFalse, "Processing", "Processing subscription")
		result = NewReconcileResultWithResource(ResourceSubscription, sub.Name, sub.Namespace, 1)
		return
	}

	// Identify (or create) the CAPTenant owned by this Subscription
	tenant, err := c.getOrCreateSubscriptionTenant(ctx, sub)
	if err != nil {
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateError, metav1.ConditionFalse, "TenantError", err.Error())
		return
	}

	// Wait for the owned tenant to become ready
	if !isCROConditionReady(tenant.Status.GenericStatus) {
		if tenant.Status.State == v1alpha1.CAPTenantStateProvisioningError || tenant.Status.State == v1alpha1.CAPTenantStateUpgradeError {
			err = fmt.Errorf("tenant %s.%s in state %s", tenant.Namespace, tenant.Name, tenant.Status.State)
			sub.SetStatusCondition(string(v1alpha1.ConditionTypeTenantReady), metav1.ConditionFalse, "TenantError", err.Error())
			sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateError, metav1.ConditionFalse, "TenantError", err.Error())
			return
		}

		msg := fmt.Sprintf("waiting for tenant %s.%s to be ready", tenant.Namespace, tenant.Name)
		util.LogInfo("Waiting for tenant to be ready", string(Processing), sub, tenant, "tenantId", sub.Spec.TenantId)
		sub.SetStatusCondition(string(v1alpha1.ConditionTypeTenantReady), metav1.ConditionFalse, "TenantNotReady", msg)
		sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateProcessing, metav1.ConditionFalse, "TenantNotReady", msg)
		result = NewReconcileResultWithResource(ResourceSubscription, sub.Name, sub.Namespace, defaultResourceDelay)
		return
	}

	// Tenant is ready --> mark the Subscription ready
	sub.SetStatusCondition(string(v1alpha1.ConditionTypeTenantReady), metav1.ConditionTrue, "TenantReady", "Tenant is ready")
	sub.SetStatusWithReadyCondition(v1alpha1.SubscriptionStateReady, metav1.ConditionTrue, "Ready", "Subscription is ready")
	return
}

// getOrCreateSubscriptionTenant identifies an existing CAPTenant for the subscription (via subscriptionGuid) or creates one owned by the Subscription.
func (c *Controller) getOrCreateSubscriptionTenant(ctx context.Context, sub *v1alpha1.Subscription) (*v1alpha1.CAPTenant, error) {
	// First check if a tenant already exists for this subscription (identified by subscriptionGuid)
	tenant, err := c.getSubscriptionTenant(sub)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	// No tenant found; create one using the providerSubaccountId + btpAppName to identify the owning application (AppIdHash)
	return c.createSubscriptionTenant(ctx, sub)
}

// getSubscriptionTenant looks up the CAPTenant for the subscription using the subscriptionGuid (and tenantId) labels.
func (c *Controller) getSubscriptionTenant(sub *v1alpha1.Subscription) (*v1alpha1.CAPTenant, error) {
	selector, err := labels.ValidatedSelectorFromSet(map[string]string{
		MetadataSubscriptionGUID: sub.Spec.SubscriptionGuid,
		LabelTenantId:            sub.Spec.TenantId,
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
func (c *Controller) createSubscriptionTenant(ctx context.Context, sub *v1alpha1.Subscription) (*v1alpha1.CAPTenant, error) {
	appIdHash := sha1Sum(sub.Spec.ProviderSubaccountId, sub.Spec.AppName)

	util.LogInfo("Creating tenant for subscription", string(Processing), sub, nil, "tenantId", sub.Spec.TenantId, "subscriptionGuid", sub.Spec.SubscriptionGuid)

	tenant, err := c.crdClient.SmeV1alpha1().CAPTenants(sub.Namespace).Create(ctx, &v1alpha1.CAPTenant{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: sub.Name + "-",
			Namespace:    sub.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(sub, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.SubscriptionKind)),
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
			BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
				TenantId: sub.Spec.TenantId,
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
