/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	CAPApplicationEventMissingSecrets               = "MissingSecrets"
	CAPApplicationEventPrimaryGatewayModified       = "PrimaryGatewayModified"
	CAPApplicationEventMissingIngressGatewayInfo    = "MissingIngressGatewayInfo"
	CAPApplicationEventProviderTenantCreated        = "ProviderTenantCreated"
	CAPApplicationEventNewCAVTriggeredTenantUpgrade = "NewCAVTriggeredTenantUpgrade"
)

const (
	EventActionProcessingSecrets        = "ProcessingSecrets"
	EventActionProviderTenantProcessing = "ProviderTenantProcessing"
	EventActionCheckForVersion          = "CheckForVersion"
)

func (c *Controller) reconcileCAPApplication(ctx context.Context, item QueueItem, attempts int) (result *ReconcileResult, err error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister()
	cached, err := lister.CAPApplications(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	ca := cached.DeepCopy()

	// prepare annotations, labels, finalizers
	if c.prepareCAPApplication(ctx, ca) {
		if err = c.updateCAPApplication(ctx, ca); err == nil {
			result = NewReconcileResultWithResource(ResourceCAPApplication, ca.Name, ca.Namespace, 0)
		}
		return
	}

	defer func() {
		// observe subdomains and queue domains (in case of changes)
		c.observeCAPApplicationSubdomains(ctx, ca, result)

		if statusErr := c.updateCAPApplicationStatus(ctx, ca); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	// check for deletion
	if ca.DeletionTimestamp != nil {
		return c.handleCAPApplicationDeletion(ctx, ca)
	}

	if genChanged := (ca.Status.State == "Consistent" && ca.Status.ObservedGeneration != ca.Generation); ca.Status.State == "" || genChanged {
		reason := "ApplicationProcessing"
		message := ""
		if genChanged {
			reason = "ResourceDefinitionChanged"
			message = "re-processing after spec update"
		}
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateProcessing, metav1.ConditionFalse, reason, message)
		result = NewReconcileResultWithResource(ResourceCAPApplication, ca.Name, ca.Namespace, 0)
	} else {
		result, err = c.handleCAPApplicationDependentResources(ctx, ca, attempts)
	}

	return c.checkAdditionalConditions(ctx, ca, result, err)
}

func (c *Controller) handleCAPApplicationDependentResources(ctx context.Context, ca *v1alpha1.CAPApplication, attempts int) (requeue *ReconcileResult, err error) {
	var processing bool
	defer func() {
		if processing {
			if requeue == nil {
				requeue = NewReconcileResult()
			}
			// requeue after 30s to check for consistency
			requeue.AddResource(ResourceCAPApplication, ca.Name, ca.Namespace, 30*time.Second)
		}
	}()

	// step 1 - validate BTPServices
	if processing, err = c.validateSecrets(ctx, ca, attempts); err != nil || processing {
		return
	}

	// step 2.1 Reconcile Service related DNS entries here --> This creates service exposure based DNS entries for all versions of the CAPApplication
	// The version ready status needs these service related DNS entries to exist!
	// err = c.reconcileServiceDNSEntires(ctx, ca)
	// if err != nil {
	// 	return
	// }

	// step 2.2 - check for valid versions
	cav, err := c.getLatestReadyCAPApplicationVersion(ctx, ca, true)
	if err != nil {
		// do not update the CAPApplication status - this is not an error reported by the version, but error while fetching the version
		return
	}
	if cav == nil {
		processing = true
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateProcessing, metav1.ConditionFalse, "WaitingForReadyCAPApplicationVersion", "")
		// Update additional condition `LatestVersionReady` to False
		ca.SetStatusCondition(string(v1alpha1.ConditionTypeLatestVersionReady), metav1.ConditionFalse, "WaitingForReadyCAPApplicationVersion", "")
		return
	}
	// Check if this is a services only scenario and update the Status accordingly
	if err = c.checkServicesOnly(ca, cav); err != nil {
		// Update additional condition `LatestVersionReady` to False with error from checkServicesOnly
		ca.SetStatusCondition(string(v1alpha1.ConditionTypeLatestVersionReady), metav1.ConditionFalse, "WaitingForReadyCAPApplicationVersion", err.Error())
		return
	}
	// We can already update LatestVersionReady to "true" at this point in time, but as this method is called several times, we do not do it here (during initial Provisioning as CA itself is may not be Consistent)

	// step 3 - queue domain handling
	// if requeue, err = c.handleDomains(ctx, ca); requeue != nil || err != nil {
	// 	return
	// }

	// step 4 - validate provider tenant, create if not available
	if processing, err = c.reconcileCAPApplicationProviderTenant(ctx, ca, cav); err != nil || processing {
		return
	}

	// step 5 - reconcile service exposure, create/update services based on the latest CAV
	if requeue, err = c.reconcileServiceNetworking(ctx, ca, cav); requeue != nil || err != nil {
		return
	}

	// step 6 - check state of dependent resources
	// if processing, err = c.checkPrimaryDomainResources(ctx, ca); err != nil || processing {
	// 	return
	// }

	// step 7 - check and set consistent status
	return c.verifyApplicationConsistent(ctx, ca)
}

func (c *Controller) verifyApplicationConsistent(ctx context.Context, ca *v1alpha1.CAPApplication) (requeue *ReconcileResult, err error) {
	if ca.Status.State != v1alpha1.CAPApplicationStateConsistent {
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateConsistent, metav1.ConditionTrue, "VersionExists", "")
		// Update additional condition `LatestVersionReady` to True
		ca.SetStatusCondition(string(v1alpha1.ConditionTypeLatestVersionReady), metav1.ConditionTrue, "VersionExists", "")
		// No tenants for services only scenario
		if !ca.IsServicesOnly() {
			// Update additional condition `AllTenantsReady` to True
			ca.SetStatusCondition(string(v1alpha1.ConditionTypeAllTenantsReady), metav1.ConditionTrue, "ProviderTenantReady", "")
		}
	}

	// Check for newer CAPApplicationVersion
	return nil, c.checkNewCAPApplicationVersion(ctx, ca)
}

func (c *Controller) checkNewCAPApplicationVersion(ctx context.Context, ca *v1alpha1.CAPApplication) error {
	cav, err := c.getLatestReadyCAPApplicationVersion(ctx, ca, false)
	if err != nil {
		return err
	}

	// Get all relevant tenants
	tenants, err := c.getRelevantTenantsForCA(ca)
	if err != nil || len(tenants) == 0 {
		return err
	}
	updated := false
	for _, tenant := range tenants {
		if tenant.Spec.VersionUpgradeStrategy == v1alpha1.VersionUpgradeStrategyTypeNever {
			// Skip non relevant tenants
			continue
		}
		if tenant.Status.State == v1alpha1.CAPTenantStateProvisioning || tenant.Status.State == v1alpha1.CAPTenantStateUpgrading || tenant.Status.State == v1alpha1.CAPTenantStateDeleting {
			// Skip tenants that are not ready or not in processing or not in error
			continue
		}
		// Assume we may have to update the tenant and prepare a copy
		cat := tenant.DeepCopy()

		// Check version of tenant
		if cat.Spec.Version != cav.Spec.Version {
			// update CAPTenant Spec to point to the latest version
			cat.Spec.Version = cav.Spec.Version
			// Trigger update on CAPTenant (modifies Generation) --> which would reconcile the tenant
			if _, err = c.crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).Update(ctx, cat, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("could not update %s %s.%s: %w", v1alpha1.CAPTenantKind, cat.Namespace, cat.Name, err)
			}
			c.Event(tenant, ca, corev1.EventTypeNormal, CAPTenantEventAutoVersionUpdate, EventActionUpgrade, fmt.Sprintf("version updated to %s for initiating tenant upgrade", cav.Spec.Version))
			updated = true
		}
	}
	if updated {
		msg := fmt.Sprintf("new version %s.%s was used to trigger tenant upgrades", cav.Namespace, cav.Name)
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateProcessing, metav1.ConditionFalse, CAPApplicationEventNewCAVTriggeredTenantUpgrade, msg)
		ca.SetStatusCondition(string(v1alpha1.ConditionTypeLatestVersionReady), metav1.ConditionTrue, string(v1alpha1.ConditionTypeLatestVersionReady), "")
		ca.SetStatusCondition(string(v1alpha1.ConditionTypeAllTenantsReady), metav1.ConditionFalse, "UpgradingTenants", "")
		c.Event(ca, nil, corev1.EventTypeNormal, CAPApplicationEventNewCAVTriggeredTenantUpgrade, EventActionCheckForVersion, msg)
	}
	return nil
}

func (c *Controller) checkAdditionalConditions(ctx context.Context, ca *v1alpha1.CAPApplication, result *ReconcileResult, err error) (*ReconcileResult, error) {
	// In case of explicit Reconcile or errors return back with the original result
	if result != nil || err != nil {
		return result, err
	}

	// Check and update additional status conditions
	// Set ready Condition and Reason for Version check LatestVersionNotReady = True
	readyCondition := metav1.ConditionTrue
	readyReason := string(v1alpha1.ConditionTypeLatestVersionReady)

	// Get latest CAV (incl. ones that may not be ready)
	cav, err := c.getLatestCAPApplicationVersion(ctx, ca)
	if err != nil {
		return nil, err
	}
	// When the latest CAV is not Ready --> LatestVersionNotReady = False
	if cav.Status.State != v1alpha1.CAPApplicationVersionStateReady {
		readyCondition = metav1.ConditionFalse
		readyReason = "LatestVersionNotReady"
	}

	// Update `LatestVersionReady` status condition
	ca.SetStatusCondition(string(v1alpha1.ConditionTypeLatestVersionReady), readyCondition, readyReason, "")

	// No tenants for services only scenario
	if ca.IsServicesOnly() {
		return nil, nil
	}

	// Reset ready Condition and Reason for Tenant check AllTenantsReady --> True
	readyCondition = metav1.ConditionTrue
	readyReason = string(v1alpha1.ConditionTypeAllTenantsReady)

	// Get all relevant tenants
	tenants, err := c.getRelevantTenantsForCA(ca)
	if err != nil {
		return nil, err
	}
	for _, tenant := range tenants {
		// When a Tenant state is not Ready -or- when version of tenant (with VersionUpgradeStrategy = always) does not match the latest CAV version --> AllTenantsReady = False
		if tenant.Status.State != v1alpha1.CAPTenantStateReady || (tenant.Spec.VersionUpgradeStrategy == v1alpha1.VersionUpgradeStrategyTypeAlways && cav.Spec.Version != tenant.Spec.Version) {
			readyCondition = metav1.ConditionFalse
			readyReason = "NotAllTenantsReady"
			break
		}
	}
	// Update `AllTenantsReady` status condition
	ca.SetStatusCondition(string(v1alpha1.ConditionTypeAllTenantsReady), readyCondition, readyReason, "")

	return nil, nil
}

func (c *Controller) updateCAPApplication(ctx context.Context, ca *v1alpha1.CAPApplication) error {
	caUpdated, err := c.crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).Update(ctx, ca, metav1.UpdateOptions{})
	// Update reference to the resource
	if caUpdated != nil {
		*ca = *caUpdated
	}
	return err
}

func (c *Controller) updateCAPApplicationStatus(ctx context.Context, ca *v1alpha1.CAPApplication) error {
	if isDeletionImminent(&ca.ObjectMeta) {
		return nil
	}
	caUpdated, err := c.crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).UpdateStatus(ctx, ca, metav1.UpdateOptions{})
	// update reference to the resource
	if caUpdated != nil {
		*ca = *caUpdated
	}
	return err
}

func (c *Controller) observeCAPApplicationSubdomains(ctx context.Context, ca *v1alpha1.CAPApplication, result *ReconcileResult) error {
	mapSubDomains := map[string]struct{}{}

	// Get all versions
	cavs, err := c.getCachedCAPApplicationVersions(ctx, ca)
	if err != nil {
		return err
	}
	// Get all unique subdomains from all versions
	for _, cav := range cavs {
		for _, serviceExposure := range cav.Spec.ServiceExposures {
			mapSubDomains[serviceExposure.SubDomain] = struct{}{}
		}
	}

	// Get all tenants
	tenants, err := c.getRelevantTenantsForCA(ca)
	if err != nil {
		return err
	}
	// Add tenant subdomains
	for _, tenant := range tenants {
		mapSubDomains[tenant.Spec.SubDomain] = struct{}{}
	}

	values := slices.Sorted(maps.Keys(mapSubDomains))
	if sha256Sum(values...) != sha256Sum(ca.Status.ObservedSubdomains...) {
		ca.SetStatusObservedSubdomains(values)
		if result == nil {
			result = NewReconcileResult()
		}
		for _, ref := range ca.Spec.DomainRefs {
			switch ref.Kind {
			case v1alpha1.DomainKind:
				result.AddResource(ResourceDomain, ref.Name, ca.Namespace, 0)
			case v1alpha1.ClusterDomainKind:
				result.AddResource(ResourceClusterDomain, ref.Name, corev1.NamespaceAll, 0)
			}
		}
	}

	return nil
}

func (c *Controller) validateSecrets(ctx context.Context, ca *v1alpha1.CAPApplication, attempts int) (bool, error) {
	err := c.checkAndPreserveSecrets(ca.Spec.BTP.Services, ca.Namespace)

	if err == nil {
		return false, nil
	} else if !k8sErrors.IsNotFound(err) {
		// TODO -> clarify whether we need to set this in the status, as this is an error probably caused via api-server unavailability / connection issues
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProcessingSecretsError", err.Error())
		return false, err
	}

	// waiting for secrets
	message := fmt.Sprintf("waiting for secrets to get ready for %s %s.%s", v1alpha1.CAPApplicationKind, ca.Name, ca.Namespace)

	util.LogInfo("Waiting for secrets", string(Processing), ca, nil)
	c.Event(ca, nil, corev1.EventTypeWarning, CAPApplicationEventMissingSecrets, EventActionProcessingSecrets, message)
	ca.SetStatusWithReadyCondition(ca.Status.State, metav1.ConditionFalse, EventActionProcessingSecrets, message)
	return true, nil
}

func (c *Controller) getRelevantTenantsForCA(ca *v1alpha1.CAPApplication) ([]*v1alpha1.CAPTenant, error) {
	// No tenants for services only scenario
	if ca.IsServicesOnly() {
		return []*v1alpha1.CAPTenant{}, nil
	}
	tenantLabels := map[string]string{
		LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName),
	}
	selector, err := labels.ValidatedSelectorFromSet(tenantLabels)
	if err != nil {
		return nil, err
	}

	return c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().List(selector)
}

func (c *Controller) reconcileCAPApplicationProviderTenant(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) (bool, error) {
	// No tenants for services only scenario
	if ca.IsServicesOnly() {
		return false, nil
	}
	providerTenantName := strings.Join([]string{ca.Name, ProviderTenantType}, "-")
	tenant, err := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().CAPTenants(ca.Namespace).Get(providerTenantName)
	if err != nil {
		if !k8sErrors.IsNotFound(err) {
			ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProviderTenantError", err.Error())
			return false, err
		}

		// Create a secret with the provider subscription context (dervied from the spec of CAPApplication)
		// Try to get the provider subaccount id from the annotations
		providerSubAccountId := ca.Annotations[AnnotationProviderSubAccountId]
		// If no provider subaccount id annotation is found use provider tenantId that is needed because some cds / hana APIs seem to rely on this field instead of tenantId!
		if providerSubAccountId == "" {
			providerSubAccountId = ca.Spec.Provider.TenantId
		}
		secret, err := c.kubeClient.CoreV1().Secrets(ca.Namespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: providerTenantName + "-",
				Namespace:    ca.Namespace,
				Labels: map[string]string{
					LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName),
					LabelTenantId:                     ca.Spec.Provider.TenantId,
				},
			},
			StringData: map[string]string{
				SubscriptionContext: `{
					"subscriptionAppName": "` + ca.Spec.BTPAppName + `",
					"subscribedTenantId": "` + ca.Spec.Provider.TenantId + `",
					"subscribedSubaccountId": "` + providerSubAccountId + `",
					"subscribedSubdomain": "` + ca.Spec.Provider.SubDomain + `",
					"globalAccountGUID": "` + ca.Spec.GlobalAccountId + `"
				}`,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			util.LogError(err, "Error creating tenant subscription context secret", string(Processing), ca, nil, "tenantId", ca.Spec.Provider.TenantId)
			ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProviderTenantError", err.Error())
			return false, err
		}

		// Create provider tenant
		util.LogInfo("Creating provider tenant", string(Processing), ca, nil, "tenantId", ca.Spec.Provider.TenantId)

		if tenant, err = c.crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).Create(
			ctx, &v1alpha1.CAPTenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      providerTenantName,
					Namespace: ca.Namespace,
					Annotations: map[string]string{
						AnnotationBTPApplicationIdentifier:  ca.Spec.GlobalAccountId + "." + ca.Spec.BTPAppName,
						AnnotationSubscriptionContextSecret: secret.Name, // Store the secret name in the tenant annotation

					},
					Labels: map[string]string{
						LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName),
						LabelTenantType:                   ProviderTenantType,
						LabelTenantId:                     ca.Spec.Provider.TenantId,
					},
				},
				Spec: v1alpha1.CAPTenantSpec{
					CAPApplicationInstance: ca.Name,
					BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
						SubDomain: ca.Spec.Provider.SubDomain,
						TenantId:  ca.Spec.Provider.TenantId,
					},
					Version: cav.Spec.Version,
				},
			}, metav1.CreateOptions{}); err != nil {
			ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProviderTenantError", err.Error())
			return false, err
		}
		if tenant != nil {
			secret.OwnerReferences = []metav1.OwnerReference{
				*metav1.NewControllerRef(tenant, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind)),
			}
			_, err = c.kubeClient.CoreV1().Secrets(tenant.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
			if err != nil {
				util.LogError(err, "Error updating tenant subscription context secret", string(Processing), ca, nil, "tenantId", ca.Spec.Provider.TenantId)
				ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProviderTenantError", err.Error())
				return false, err
			}
		}
		c.Event(ca, tenant, corev1.EventTypeNormal, CAPApplicationEventProviderTenantCreated, EventActionProviderTenantProcessing, fmt.Sprintf("created provider tenant %s.%s", tenant.Namespace, tenant.Name))
	}
	if !isCROConditionReady(tenant.Status.GenericStatus) {
		// Upgrade errors also handled
		if tenant.Status.State == v1alpha1.CAPTenantStateProvisioningError || tenant.Status.State == v1alpha1.CAPTenantStateUpgradeError {
			err = fmt.Errorf("provider %s in state %s for %s %s.%s", v1alpha1.CAPTenantKind, tenant.Status.State, v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
			ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "ProviderTenantError", err.Error())
			return false, err
		}

		msg := fmt.Sprintf("provider %v not ready for %v %v.%v; waiting for it to be ready", v1alpha1.CAPTenantKind, v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
		util.LogInfo("Waiting for provider tenant to be ready", string(Processing), ca, tenant, "tenantId", ca.Spec.Provider.TenantId)
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateProcessing, metav1.ConditionFalse, EventActionProviderTenantProcessing, msg)
		return true, nil
	}

	return false, nil
}

func (c *Controller) handleCAPApplicationDeletion(ctx context.Context, ca *v1alpha1.CAPApplication) (*ReconcileResult, error) {
	var err error

	util.LogInfo("Attempting to delete application", string(Deleting), ca, nil)
	if ca.Status.State != v1alpha1.CAPApplicationStateDeleting {
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateDeleting, metav1.ConditionFalse, "DeleteTriggered", "")
		return NewReconcileResultWithResource(ResourceCAPApplication, ca.Name, ca.Namespace, 0), nil
	}

	// TODO: cleanup domain resources via reconciliation
	util.LogInfo("Removing primary domain certificate", string(Deleting), ca, nil)
	if err = c.deletePrimaryDomainCertificate(ctx, ca); err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}
	if !ca.IsServicesOnly() {
		// delete CAPTenants - return if found in this loop, to verify deletion
		var tenantFound bool
		util.LogInfo("Deleting dependent tenants", string(Deleting), ca, nil)
		if tenantFound, err = c.deleteTenants(ctx, ca); tenantFound || err != nil {
			util.LogError(err, "Could not delete dependent tenant", string(Deleting), ca, nil)
			return nil, err
		}
	}

	util.LogInfo("Cleaning up secrets", string(Deleting), ca, nil)
	if err = c.cleanupPreservedSecrets(ca.Spec.BTP.Services, ca.Namespace); err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}

	// delete CAPApplication
	if removeFinalizer(&ca.Finalizers, FinalizerCAPApplication) {
		util.LogInfo("Removing Finalizer; finished deleting this application", string(Deleting), ca, nil)
		return nil, c.updateCAPApplication(ctx, ca)
	}

	return nil, nil
}

func (c *Controller) deleteTenants(ctx context.Context, ca *v1alpha1.CAPApplication) (bool, error) {
	tenants, err := c.getRelevantTenantsForCA(ca)
	if err != nil {
		return false, err
	}

	// delete tenants - if not triggered yet
	for _, tenant := range tenants {
		if tenant.DeletionTimestamp == nil {
			if err = c.crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).Delete(ctx, tenant.Name, metav1.DeleteOptions{}); err != nil {
				return true, err
			}
		}
	}

	return len(tenants) > 0, nil
}

func (c *Controller) prepareCAPApplication(ctx context.Context, ca *v1alpha1.CAPApplication) (update bool) {
	// Do nothing when object is deleted
	if ca.DeletionTimestamp != nil {
		return false
	}
	// add Finalizer to prevent direct deletion
	if ca.Finalizers == nil {
		ca.Finalizers = []string{}
	}
	if addFinalizer(&ca.Finalizers, FinalizerCAPApplication) {
		update = true
	}

	// add Label/Annotation for BTP App
	appMetadata := appMetadataIdentifiers{
		globalAccountId: ca.Spec.GlobalAccountId,
		appName:         ca.Spec.BTPAppName,
	}
	if updateLabelAnnotationMetadata(&ca.ObjectMeta, &appMetadata) {
		update = true
	}

	return update
}
