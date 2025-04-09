/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

type IdentifiedCAPTenantOperations struct {
	active    []v1alpha1.CAPTenantOperation
	processed []v1alpha1.CAPTenantOperation
}

type CAPTenantOperationTypeSelector string

type CAPTenantStateHandlerFunc func(ctx context.Context, c *Controller, cat *v1alpha1.CAPTenant, target StateCondition, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error)

type StateCondition struct {
	state           v1alpha1.CAPTenantState
	conditionReason string
	conditionStatus metav1.ConditionStatus
}

type TargetStateHandler struct {
	target  StateCondition
	handler CAPTenantStateHandlerFunc
}

type StatusInfo struct {
	failed     TargetStateHandler
	completed  TargetStateHandler
	processing TargetStateHandler
}

const (
	CAPTenantOperationTypeSelectorAll            CAPTenantOperationTypeSelector = "All"
	CAPTenantOperationTypeSelectorUpgrade        CAPTenantOperationTypeSelector = CAPTenantOperationTypeSelector(v1alpha1.CAPTenantOperationTypeUpgrade)
	CAPTenantOperationTypeSelectorProvisioning   CAPTenantOperationTypeSelector = CAPTenantOperationTypeSelector(v1alpha1.CAPTenantOperationTypeProvisioning)
	CAPTenantOperationTypeSelectorDeprovisioning CAPTenantOperationTypeSelector = CAPTenantOperationTypeSelector(v1alpha1.CAPTenantOperationTypeDeprovisioning)
)

const (
	CAPTenantEventProcessingStarted                 = "ProcessingStarted"
	CAPTenantEventProvisioningFailed                = "ProvisioningFailed"
	CAPTenantEventProvisioningCompleted             = "ProvisioningCompleted"
	CAPTenantEventProvisioningOperationCreated      = "ProvisioningOperationCreated"
	CAPTenantEventDeprovisioningFailed              = "DeprovisioningFailed"
	CAPTenantEventDeprovisioningCompleted           = "DeprovisioningCompleted"
	CAPTenantEventDeprovisioningOperationCreated    = "DeprovisioningOperationCreated"
	CAPTenantEventUpgradeFailed                     = "UpgradeFailed"
	CAPTenantEventUpgradeCompleted                  = "UpgradeCompleted"
	CAPTenantEventUpgradeOperationCreated           = "UpgradeOperationCreated"
	CAPTenantEventTenantNetworkingModified          = "TenantNetworkingModified"
	CAPTenantEventVirtualServiceModificationFailed  = "VirtualServiceModificationFailed"
	CAPTenantEventDestinationRuleModificationFailed = "DestinationRuleModificationFailed"
	CAPTenantEventInvalidReference                  = "InvalidReference"
	CAPTenantEventAutoVersionUpdate                 = "AutoVersionUpdate"
)

const (
	EventActionReconcileTenantNetworking = "ReconcileTenantNetworking"
	EventActionPrepare                   = "Prepare"
	EventActionUpgrade                   = "Upgrade"
)

var operationTypeMsgMap = map[v1alpha1.CAPTenantOperationType]string{
	v1alpha1.CAPTenantOperationTypeProvisioning:   string(Provisioning),
	v1alpha1.CAPTenantOperationTypeUpgrade:        string(Upgrading),
	v1alpha1.CAPTenantOperationTypeDeprovisioning: string(Deprovisioning),
}

// maps tenant operation types (and their status) to CAPTenant status changes
var TenantOperationStatusMap = map[v1alpha1.CAPTenantOperationType]StatusInfo{
	v1alpha1.CAPTenantOperationTypeProvisioning: {
		failed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateProvisioningError, conditionReason: CAPTenantEventProvisioningFailed, conditionStatus: metav1.ConditionFalse},
			handler: handleFailingTenantOperation,
		},
		completed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateReady, conditionReason: CAPTenantEventProvisioningCompleted, conditionStatus: metav1.ConditionTrue},
			handler: handleCompletedProvisioningUpgradeOperation,
		},
		processing: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateProvisioning, conditionReason: CAPTenantEventProvisioningOperationCreated, conditionStatus: metav1.ConditionFalse},
			handler: handleWaitingForTenantOperation,
		},
	},
	v1alpha1.CAPTenantOperationTypeUpgrade: { // NOTE: during upgrades the ready condition status remains "True" as the tenant is in use
		failed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateUpgradeError, conditionReason: CAPTenantEventUpgradeFailed, conditionStatus: metav1.ConditionTrue},
			handler: handleFailingTenantOperation,
		},
		completed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateReady, conditionReason: CAPTenantEventUpgradeCompleted, conditionStatus: metav1.ConditionTrue},
			handler: handleCompletedProvisioningUpgradeOperation,
		},
		processing: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateUpgrading, conditionReason: CAPTenantEventUpgradeOperationCreated, conditionStatus: metav1.ConditionTrue},
			handler: handleWaitingForTenantOperation,
		},
	},
	v1alpha1.CAPTenantOperationTypeDeprovisioning: {
		failed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateDeleting, conditionReason: CAPTenantEventDeprovisioningFailed, conditionStatus: metav1.ConditionFalse},
			handler: handleFailingTenantOperation,
		},
		completed: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateDeleting, conditionReason: CAPTenantEventDeprovisioningCompleted, conditionStatus: metav1.ConditionFalse},
			handler: removeTenantFinalizers,
		},
		processing: TargetStateHandler{
			target:  StateCondition{state: v1alpha1.CAPTenantStateDeleting, conditionReason: CAPTenantEventDeprovisioningOperationCreated, conditionStatus: metav1.ConditionFalse},
			handler: handleWaitingForTenantOperation,
		},
	},
}

func getTenantReconcileResultConsideringDeletion(cat *v1alpha1.CAPTenant, fallback *ReconcileResult) *ReconcileResult {
	if cat.DeletionTimestamp != nil && cat.Status.State != v1alpha1.CAPTenantStateDeleting {
		return NewReconcileResultWithResource(ResourceCAPTenant, cat.Name, cat.Namespace, 15*time.Second)
	}
	return fallback
}

var handleWaitingForTenantOperation = func(ctx context.Context, c *Controller, cat *v1alpha1.CAPTenant, target StateCondition, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error) {
	// NOTE: not returning a requeue item is ok, as changes in CAPTenantOperation status will queue the item via the informer
	util.LogInfo("Waiting for tenant operation to complete", operationTypeMsgMap[ctop.Spec.Operation], cat, ctop, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
	cat.SetStatusWithReadyCondition(target.state, target.conditionStatus, target.conditionReason, fmt.Sprintf("waiting for %s %s.%s of type %s to complete", v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name, ctop.Spec.Operation))
	return NewReconcileResultWithResource(ResourceCAPTenant, cat.Name, cat.Namespace, 15*time.Second), nil // requeue while the tenant operation is being processed
}

var handleCompletedProvisioningUpgradeOperation = func(ctx context.Context, c *Controller, cat *v1alpha1.CAPTenant, target StateCondition, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error) {
	util.LogInfo("Tenant operation successfully completed", operationTypeMsgMap[ctop.Spec.Operation], cat, ctop, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
	message := fmt.Sprintf("%s %s.%s successfully completed", v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
	c.Event(cat, ctop, corev1.EventTypeNormal, target.conditionReason, string(target.state), message)

	ca, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(cat.Namespace).Get(cat.Spec.CAPApplicationInstance)
	if err != nil {
		return nil, err
	}
	// check for dns entries only when there are secondary domains
	if len(ca.Spec.Domains.Secondary) > 0 {
		// Check if all Tenant DNSEntries are Ready
		processing, err := c.checkDNSEntries(ctx, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
		if err != nil {
			util.LogError(err, "DNS entries error", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
			return nil, err
		}
		if processing {
			util.LogInfo("DNS entry resource not ready", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
			// requeue to iterate this check after a delay
			return NewReconcileResultWithResource(ResourceCAPTenant, cat.Name, cat.Namespace, 10*time.Second), nil
		}
	}

	// check and reconcile tenant virtual service
	// adjust virtual service only when tenant is finalizing (after provisioning or upgrade)
	requeue, err := c.reconcileTenantNetworking(ctx, cat, ctop.Spec.CAPApplicationVersionInstance, ca)
	if err != nil || requeue != nil {
		return requeue, err
	}

	// the ObservedGeneration of the tenant should be updated here (when Ready)
	cat.SetStatusWithReadyCondition(target.state, target.conditionStatus, target.conditionReason, message)
	cat.SetStatusCAPApplicationVersion(ctop.Spec.CAPApplicationVersionInstance)
	return getTenantReconcileResultConsideringDeletion(cat, nil), nil
}

var handleFailingTenantOperation = func(ctx context.Context, c *Controller, cat *v1alpha1.CAPTenant, target StateCondition, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error) {
	var (
		message string
		related runtime.Object = nil
	)
	if ctop == nil {
		message = fmt.Sprintf("Could not identify %s for tenant state %s", v1alpha1.CAPTenantOperationKind, cat.Status.State)
		util.LogInfo(message, string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
	} else {
		message = fmt.Sprintf("%s %s.%s failed", v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
		util.LogInfo("Tenant operation failed", operationTypeMsgMap[ctop.Spec.Operation], cat, ctop, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		related = ctop
	}

	c.Event(cat, related, corev1.EventTypeWarning, target.conditionReason, string(target.state), message)
	cat.SetStatusWithReadyCondition(target.state, target.conditionStatus, target.conditionReason, message)
	return getTenantReconcileResultConsideringDeletion(cat, nil), nil
}

var removeTenantFinalizers = func(ctx context.Context, c *Controller, cat *v1alpha1.CAPTenant, target StateCondition, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error) {
	if ctop != nil {
		c.Event(cat, ctop, corev1.EventTypeNormal, target.conditionReason, string(target.state), fmt.Sprintf("%s of %s %s.%s successfully completed; attempting to remove finalizers", ctop.Spec.Operation, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name))
	}

	// remove known finalizer
	if removeFinalizer(&cat.Finalizers, FinalizerCAPTenant) {
		util.LogInfo("Removing finalizer; finished deleting this tenant", string(Deleting), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		return c.updateCAPTenant(ctx, cat, false)
	}
	return nil, nil
}

func (c *Controller) reconcileCAPTenant(ctx context.Context, item QueueItem, attempts int) (requeue *ReconcileResult, err error) {
	cached, err := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().CAPTenants(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	cat := cached.DeepCopy()

	defer func() {
		if statusErr := c.updateCAPTenantStatus(ctx, cat); statusErr != nil && err != nil {
			err = statusErr
		}
	}()

	// prepare owner refs, labels, finalizers
	if update, err := c.prepareCAPTenant(ctx, cat); err != nil {
		return nil, err
	} else if update {
		return c.updateCAPTenant(ctx, cat, true)
	}

	// Skip processing until the right version is set on the CAPTenant (via CAPApplication)
	// This indirectly ensures that we do not create duplicate tenant operations for consumer tenant provisioning scenarios!
	if cat.Spec.Version == "" {
		util.LogInfo("Tenant without version detected, skip processing until version is set", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		return requeue, nil
	}

	// if cat.DeletionTimestamp == nil {
	// 	// Create relevant DNSEntries for this tenant. DNS entries are checked before setting the tenant as ready
	// 	if err = c.reconcileTenantDNSEntries(ctx, cat); err != nil {
	// 		return
	// 	}
	// }

	// create and track CAPTenantOperations based on state, deletion timestamp, version change etc.
	requeue, err = c.handleTenantOperationsForCAPTenant(ctx, cat)
	if err != nil || requeue != nil {
		return
	}

	if cat.DeletionTimestamp == nil && cat.Status.CurrentCAPApplicationVersionInstance != "" {
		requeue, err = c.reconcileTenantNetworking(ctx, cat, cat.Status.CurrentCAPApplicationVersionInstance, nil)
		if requeue == nil && err == nil {
			util.LogInfo("Tenant processing completed", string(Ready), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		}
	}

	return
}

func (c *Controller) updateCAPTenant(ctx context.Context, cat *v1alpha1.CAPTenant, requeue bool) (result *ReconcileResult, err error) {
	var catUpdated *v1alpha1.CAPTenant
	catUpdated, err = c.crdClient.SmeV1alpha1().CAPTenants(cat.Namespace).Update(ctx, cat, metav1.UpdateOptions{})
	// Update reference to the resource
	if catUpdated != nil {
		*cat = *catUpdated
	}
	if requeue {
		result = NewReconcileResultWithResource(ResourceCAPTenant, cat.Name, cat.Namespace, 0)
	}
	return
}

func findLatestCreatedTenantOperation(ops []v1alpha1.CAPTenantOperation, selector CAPTenantOperationTypeSelector) (latest *v1alpha1.CAPTenantOperation) {
	for _, op := range ops {
		// workaround to fix pointer resolution after loop -> https://stackoverflow.com/questions/45967305/copying-the-address-of-a-loop-variable-in-go
		ctop := op
		if selector != CAPTenantOperationTypeSelectorAll && CAPTenantOperationTypeSelector(ctop.Spec.Operation) != selector {
			continue
		}
		if latest == nil || ctop.CreationTimestamp.After(latest.CreationTimestamp.Time) {
			latest = &ctop
		}
	}

	return latest
}

func findCAPTenantOperationTypeFromProcessingState(state v1alpha1.CAPTenantState) v1alpha1.CAPTenantOperationType {
	var opType v1alpha1.CAPTenantOperationType
	for k, v := range TenantOperationStatusMap {
		if v.processing.target.state == state {
			opType = k
			break
		}
	}
	return opType
}

func isTenantOperationConditionFailed(ctop *v1alpha1.CAPTenantOperation) bool {
	ready := ctop.Status.GenericStatus.Conditions[0]
	// NOTE: check reason != StepCompleted, instead of == StepFailed (operation could fail because of multiple reasons)
	if ready.Status == metav1.ConditionTrue && ready.Reason != CAPTenantOperationConditionReasonStepCompleted {
		return true
	}
	return false
}

func (c *Controller) handleTenantOperationsForCAPTenant(ctx context.Context, cat *v1alpha1.CAPTenant) (*ReconcileResult, error) {
	ops, err := c.getCAPTenantOperationsByType(ctx, cat, CAPTenantOperationTypeSelectorAll)
	if err != nil {
		return nil, err
	}

	// [1] wait for active operations to complete
	if len(ops.active) > 0 {
		if len(ops.active) > 1 {
			util.LogInfo("Identified multiple active tenant operations", string(Processing), cat, nil, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
		}
		ctop := findLatestCreatedTenantOperation(ops.active, CAPTenantOperationTypeSelectorAll)
		targetInfo := TenantOperationStatusMap[ctop.Spec.Operation].processing
		return targetInfo.handler(ctx, c, cat, targetInfo.target, ctop)
	}

	// [2] look for operations which have recently finished and set status accordingly
	if cat.Status.State == v1alpha1.CAPTenantStateProvisioning || cat.Status.State == v1alpha1.CAPTenantStateUpgrading || cat.Status.State == v1alpha1.CAPTenantStateDeleting {
		opType := findCAPTenantOperationTypeFromProcessingState(cat.Status.State)
		ctop := findLatestCreatedTenantOperation(ops.processed, CAPTenantOperationTypeSelector(opType))
		var targetInfo TargetStateHandler
		if ctop != nil {
			if isTenantOperationConditionFailed(ctop) { // operation state is failed or the operation does not exist
				targetInfo = TenantOperationStatusMap[opType].failed
			} else { // operation state is completed
				targetInfo = TenantOperationStatusMap[opType].completed
			}
			return targetInfo.handler(ctx, c, cat, targetInfo.target, ctop)
		} // else => fall through to create new operation - also for deprovisioning
	}

	// [3] create new tenant operations when necessary
	return c.handleNewTenantOperations(ctx, cat, ops)
}

func (c *Controller) handleNewTenantOperations(ctx context.Context, cat *v1alpha1.CAPTenant, ops *IdentifiedCAPTenantOperations) (*ReconcileResult, error) {
	// (1)) process deletion when Deletion timestamp is set
	if cat.DeletionTimestamp != nil {
		if cat.Status.CurrentCAPApplicationVersionInstance == "" {
			// there is no valid version so far -> deprovisioning is not required
			return removeTenantFinalizers(ctx, c, cat, TenantOperationStatusMap[v1alpha1.CAPTenantOperationTypeDeprovisioning].completed.target, nil)
		} else {
			return c.triggerTenantOperation(ctx, cat, v1alpha1.CAPTenantOperationTypeDeprovisioning)
		}
	}

	// (2) Check whether a new tenant operation is required (in case of ProvisioningError / UpgradeError)
	if isRequired, err := c.isNewTenantOperationRequired(ctx, cat, ops); err != nil || !isRequired {
		return nil, err
	}

	// (3) start provisioning when there is no current version
	if cat.Status.CurrentCAPApplicationVersionInstance == "" {
		return c.triggerTenantOperation(ctx, cat, v1alpha1.CAPTenantOperationTypeProvisioning)
	}

	// (4) check for newer version to upgrade
	return c.tryForTenantUpgrade(ctx, cat)
}

func (c *Controller) isNewTenantOperationRequired(ctx context.Context, cat *v1alpha1.CAPTenant, ops *IdentifiedCAPTenantOperations) (bool, error) {
	if cat.Status.State != v1alpha1.CAPTenantStateProvisioningError && cat.Status.State != v1alpha1.CAPTenantStateUpgradeError {
		return true, nil
	}

	// find existing operation (processed) - there can be no active operations at this point in the code (active operations have already been considered)
	var opType v1alpha1.CAPTenantOperationType
	if cat.Status.State == v1alpha1.CAPTenantStateProvisioningError {
		opType = v1alpha1.CAPTenantOperationTypeProvisioning
	} else {
		opType = v1alpha1.CAPTenantOperationTypeUpgrade
	}
	ctop := findLatestCreatedTenantOperation(ops.processed, CAPTenantOperationTypeSelector(opType))
	if ctop == nil {
		// a new tenant operation is to be created when there are none existing (or older ones have been deleted manually)
		return true, nil
	}

	cav, err := c.getCAPApplicationVersionForTenantOperationType(ctx, cat, opType)
	if err != nil || cav == nil {
		return false, err
	}

	// a new tenant operation needs to be created when there is a different CAPApplicationVersion available for the lifecycle operation
	return ctop.Spec.CAPApplicationVersionInstance != cav.Name, nil
}

// create a CAPTenantOperation instance of a specific type (provisioning/deprovisioning/upgrade)
func (c *Controller) createCAPTenantOperation(ctx context.Context, cat *v1alpha1.CAPTenant, opType v1alpha1.CAPTenantOperationType) (*v1alpha1.CAPTenantOperation, error) {
	// delete all previous tenant operations of the current type
	labelsMap := map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(cat.Namespace, cat.Name),
		LabelTenantOperationType: string(opType),
	}
	selector, err := labels.ValidatedSelectorFromSet(labelsMap)
	if err != nil {
		return nil, err
	}
	err = c.crdClient.SmeV1alpha1().CAPTenantOperations(cat.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("deletion of previous %ss of type %s failed: %s", v1alpha1.CAPTenantOperationKind, opType, err.Error())
	}

	// get CAPApplicationVersion to be used for the TenantOperation job
	cav, err := c.getCAPApplicationVersionForTenantOperationType(ctx, cat, opType)
	if err != nil {
		return nil, err
	}

	// determine operation steps
	steps, err := deriveStepsForTenantOperation(cav, opType)
	if err != nil {
		return nil, err
	}

	// Cleanup all cap tenant ourputs for this tenant
	err = c.cleanUpTenantOutputs(ctx, cat)
	if err != nil {
		return nil, err
	}

	// create CAPTenantOperation
	ctop := &v1alpha1.CAPTenantOperation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       cat.Namespace,
			GenerateName:    cat.Name + "-",
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind))},
			Finalizers:      []string{FinalizerCAPTenantOperation},
		},
		Spec: v1alpha1.CAPTenantOperationSpec{
			Operation:                     opType,
			BTPTenantIdentification:       v1alpha1.BTPTenantIdentification{SubDomain: cat.Spec.SubDomain, TenantId: cat.Spec.TenantId},
			CAPApplicationVersionInstance: cav.Name,
			Steps:                         steps,
		},
	}
	addCAPTenantOperationLabels(ctop, cat) // NOTE: this is very important to do here as subsequent reconciliation of tenant will be inconsistent otherwise
	util.LogInfo("Creating tenant operation", operationTypeMsgMap[opType], cat, ctop, "tenantId", cat.Spec.TenantId, "version", cat.Spec.Version)
	return c.crdClient.SmeV1alpha1().CAPTenantOperations(cat.Namespace).Create(ctx, ctop, metav1.CreateOptions{})
}

func (c *Controller) cleanUpTenantOutputs(ctx context.Context, cat *v1alpha1.CAPTenant) error {
	// delete all tenant outputs for this tenant
	selector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelTenantId: cat.Spec.TenantId,
	})
	if err != nil {
		return err
	}
	err = c.crdClient.SmeV1alpha1().CAPTenantOutputs(cat.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return fmt.Errorf("deletion of cap tenant outputs failed: %s", err.Error())
	}
	return nil
}

func deriveStepsForTenantOperation(cav *v1alpha1.CAPApplicationVersion, opType v1alpha1.CAPTenantOperationType) (steps []v1alpha1.CAPTenantOperationStep, err error) {
	defaultSteps := func() {
		// if there are no specified steps, add only one step of type TenantOperation
		workload := getRelevantJob(v1alpha1.JobTenantOperation, cav)
		if workload == nil { // fallback to CAP workload
			workload = getRelevantDeployment(v1alpha1.DeploymentCAP, cav)
		}
		if workload == nil {
			// cannot proceed further without an identified workload
			err = fmt.Errorf("could not find workload of type %s or %s in %s %s.%s", v1alpha1.JobTenantOperation, v1alpha1.DeploymentCAP, v1alpha1.CAPApplicationVersionKind, cav.Namespace, cav.Name)
		} else {
			steps = []v1alpha1.CAPTenantOperationStep{{Name: workload.Name, Type: v1alpha1.JobTenantOperation}}
		}
	}

	if cav.Spec.TenantOperations == nil {
		defaultSteps()
		return
	}

	var ops []v1alpha1.TenantOperationWorkloadReference
	switch opType {
	case v1alpha1.CAPTenantOperationTypeProvisioning:
		ops = cav.Spec.TenantOperations.Provisioning
	case v1alpha1.CAPTenantOperationTypeDeprovisioning:
		ops = cav.Spec.TenantOperations.Deprovisioning
	case v1alpha1.CAPTenantOperationTypeUpgrade:
		ops = cav.Spec.TenantOperations.Upgrade
	}

	if len(ops) == 0 {
		defaultSteps()
		return
	}

	steps = []v1alpha1.CAPTenantOperationStep{}
	addedTenantOprJob := false
	for _, entry := range ops {
		workload := getWorkloadByName(entry.WorkloadName, cav)
		switch workload.JobDefinition.Type {
		case v1alpha1.JobTenantOperation:
			addedTenantOprJob = true
			fallthrough
		case v1alpha1.JobCustomTenantOperation:
			// continuing the tenant operation on failure is not possible for tenant operation jobs
			continueOnFailure := (workload.JobDefinition.Type != v1alpha1.JobTenantOperation) && entry.ContinueOnFailure
			steps = append(steps, v1alpha1.CAPTenantOperationStep{Name: entry.WorkloadName, Type: workload.JobDefinition.Type, ContinueOnFailure: continueOnFailure})
		default:
			continue // ignore all other types (even if specified)
		}
	}
	if !addedTenantOprJob { // ensure step of type TenantOperation is added
		return nil, fmt.Errorf("specified steps for operation %s does not contain a step of type %s", opType, v1alpha1.JobTenantOperation)
	}
	return
}

// trigger CAPTenantOperation creation and change status of tenant
func (c *Controller) triggerTenantOperation(ctx context.Context, cat *v1alpha1.CAPTenant, opType v1alpha1.CAPTenantOperationType) (*ReconcileResult, error) {
	// Create CAPTenantOperation
	ctop, err := c.createCAPTenantOperation(ctx, cat, opType)
	if err != nil {
		return nil, err
	}

	// call status handler
	targetInfo := TenantOperationStatusMap[opType].processing
	c.Event(cat, ctop, corev1.EventTypeNormal, targetInfo.target.conditionReason, string(targetInfo.target.state), fmt.Sprintf("%s %s.%s of type %s created", v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name, ctop.Spec.Operation))
	return targetInfo.handler(ctx, c, cat, targetInfo.target, ctop)
}

func (c *Controller) getCAPTenantOperationsByType(ctx context.Context, cat *v1alpha1.CAPTenant, operationTypeSelector CAPTenantOperationTypeSelector) (*IdentifiedCAPTenantOperations, error) {
	labelsMap := map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(cat.Namespace, cat.Name),
	}
	if operationTypeSelector != CAPTenantOperationTypeSelectorAll {
		labelsMap[LabelTenantOperationType] = string(operationTypeSelector)
	}
	selector, err := labels.ValidatedSelectorFromSet(labelsMap)
	if err != nil {
		return nil, err
	}

	// NOTE: do not use cache for listing (this is not a very frequent operation)
	ops, err := c.crdClient.SmeV1alpha1().CAPTenantOperations(cat.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}

	var results = IdentifiedCAPTenantOperations{active: []v1alpha1.CAPTenantOperation{}, processed: []v1alpha1.CAPTenantOperation{}}
	for _, ctop := range ops.Items {
		if isCROConditionReady(ctop.Status.GenericStatus) {
			results.processed = append(results.processed, ctop)
		} else {
			results.active = append(results.active, ctop)
		}
	}

	return &results, nil
}

func (c *Controller) getCAPApplicationVersionForTenantOperationType(ctx context.Context, cat *v1alpha1.CAPTenant, opType v1alpha1.CAPTenantOperationType) (*v1alpha1.CAPApplicationVersion, error) {
	// get owning CAPApplication
	ca, _ := c.getCachedCAPApplication(cat.Namespace, cat.Spec.CAPApplicationInstance)

	// get CAPApplication version
	switch opType {
	case v1alpha1.CAPTenantOperationTypeProvisioning, v1alpha1.CAPTenantOperationTypeUpgrade: // for provisioning or upgrade - use the relevant CAPApplicationVersion
		// get relevant CAPApplicationVersion
		cav, err := c.getRelevantCAPApplicationVersion(ctx, ca, cat.Spec.Version)
		if err != nil {
			return nil, err
		}
		util.LogInfo("Identified application version", operationTypeMsgMap[opType], cat, nil, "tenantId", cat.Spec.TenantId, "version", cav.Spec.Version)
		return cav, nil
	case v1alpha1.CAPTenantOperationTypeDeprovisioning: // for deletion - use the current CAPApplicationVersion (from status)
		if cat.Status.CurrentCAPApplicationVersionInstance == "" {
			err := fmt.Errorf("cannot identify %s for %s %s.%s", v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
			util.LogError(err, "Cannot identify applicaion version", string(Deprovisioning), cat, nil, "tenantId", cat.Spec.TenantId)
			return nil, err
		}
		cav, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions(cat.Namespace).Get(ctx, cat.Status.CurrentCAPApplicationVersionInstance, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// verify status of CAPApplicationVersion
		if !isCROConditionReady(cav.Status.GenericStatus) {
			return nil, fmt.Errorf("%s %s.%s is not %s to be used for %s", v1alpha1.CAPApplicationVersionKind, cav.Namespace, cav.Name, v1alpha1.CAPApplicationVersionStateReady, opType)
		}
		// verify owner reference
		if cav.Spec.CAPApplicationInstance != ca.Name {
			return nil, fmt.Errorf("found deviating owner references for %s %s.%s and %s %s.%s", v1alpha1.CAPApplicationVersionKind, cav.Namespace, cav.Name, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
		}
		return cav, nil
	}
	return nil, fmt.Errorf("unknown error when resolving %s for %s %s.%s", v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
}

func addCAPTenantLabels(cat *v1alpha1.CAPTenant, ca *v1alpha1.CAPApplication) (updated bool) {
	appMetadata := appMetadataIdentifiers{
		globalAccountId: ca.Spec.GlobalAccountId,
		appName:         ca.Spec.BTPAppName,
		ownerInfo: &ownerInfo{
			ownerNamespace:  ca.Namespace,
			ownerName:       ca.Name,
			ownerGeneration: ca.Generation,
		},
	}
	if updateLabelAnnotationMetadata(&cat.ObjectMeta, &appMetadata) {
		updated = true
	}
	if _, ok := cat.ObjectMeta.Labels[LabelTenantId]; !ok {
		cat.ObjectMeta.Labels[LabelTenantId] = cat.Spec.TenantId
		updated = true
	}
	if _, ok := cat.ObjectMeta.Labels[LabelTenantType]; !ok {
		if ca.Spec.Provider.TenantId == cat.Spec.TenantId {
			cat.ObjectMeta.Labels[LabelTenantType] = ProviderTenantType
		} else {
			cat.ObjectMeta.Labels[LabelTenantType] = ConsumerTenantType
		}
		updated = true
	}
	return updated
}

func (c *Controller) prepareCAPTenant(ctx context.Context, cat *v1alpha1.CAPTenant) (update bool, err error) {
	// Do nothing when object is deleted
	if cat.DeletionTimestamp != nil {
		return false, nil
	}
	ca, err := c.getCachedCAPApplication(cat.Namespace, cat.Spec.CAPApplicationInstance)
	if err != nil {
		msg := fmt.Sprintf("invalid %s reference", v1alpha1.CAPApplicationKind)
		c.Event(cat, nil, corev1.EventTypeWarning, CAPTenantEventInvalidReference, EventActionPrepare, msg)
		return false, err
	}

	// create owner reference - CAPApplication
	if _, ok := getOwnerByKind(cat.OwnerReferences, v1alpha1.CAPApplicationKind); !ok {
		cat.OwnerReferences = append(cat.OwnerReferences, *metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind)))
		update = true
	}

	if addCAPTenantLabels(cat, ca) {
		update = true
	}

	if cat.DeletionTimestamp == nil {
		// set finalizers if not added
		if cat.Finalizers == nil {
			cat.Finalizers = []string{}
		}
		if addFinalizer(&cat.Finalizers, FinalizerCAPTenant) {
			update = true
		}
	}
	return update, nil
}

func (c *Controller) tryForTenantUpgrade(ctx context.Context, cat *v1alpha1.CAPTenant) (*ReconcileResult, error) {
	// try for upgrade only when upgrade strategy is not 'never'
	if cat.Spec.VersionUpgradeStrategy == v1alpha1.VersionUpgradeStrategyTypeNever {
		return nil, nil
	}

	ca, err := c.getCachedCAPApplication(cat.Namespace, cat.Spec.CAPApplicationInstance)
	if err != nil {
		return nil, err
	}

	// fetch CAPApplicationVersion as per current tenant spec
	cav, err := c.getRelevantCAPApplicationVersion(ctx, ca, cat.Spec.Version)
	if err != nil {
		return nil, err
	}

	// compare with current version
	if cat.Status.CurrentCAPApplicationVersionInstance != cav.Name {
		// update status of the CAPTenant - ready for upgrade
		return c.triggerTenantOperation(ctx, cat, v1alpha1.CAPTenantOperationTypeUpgrade)
	}

	return nil, nil
}

func (c *Controller) updateCAPTenantStatus(ctx context.Context, cat *v1alpha1.CAPTenant) error {
	if isDeletionImminent(&cat.ObjectMeta) {
		return nil
	}

	if len(cat.Status.Conditions) == 0 {
		// initialize conditions - with processing status
		cat.SetStatusWithReadyCondition(cat.Status.State, metav1.ConditionFalse, CAPTenantEventProcessingStarted, "")
	}
	catUpdated, err := c.crdClient.SmeV1alpha1().CAPTenants(cat.Namespace).UpdateStatus(ctx, cat, metav1.UpdateOptions{})
	// update reference to the resource
	if catUpdated != nil {
		*cat = *catUpdated
	}
	return err
}

func (*Controller) enforceTenantResourceOwnership(objMeta *metav1.ObjectMeta, typeMeta *metav1.TypeMeta, cat *v1alpha1.CAPTenant) (bool, error) {
	var update bool
	// verify owner references
	if owner, ok := getOwnerByKind(objMeta.OwnerReferences, v1alpha1.CAPTenantKind); !ok {
		// set owner reference
		if objMeta.OwnerReferences == nil {
			objMeta.OwnerReferences = []metav1.OwnerReference{}
		}
		objMeta.OwnerReferences = append(objMeta.OwnerReferences, *metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind)))
		update = true
	} else if owner.Name != cat.Name {
		return false, fmt.Errorf("invalid owner reference found for %s %s.%s", typeMeta.Kind, objMeta.Namespace, objMeta.Name)
	}

	// set labels, but do not set update to true (set based on  owner reference or spec changes)
	if objMeta.Labels == nil {
		objMeta.Labels = map[string]string{}
	}
	objMeta.Labels[LabelOwnerIdentifierHash] = sha1Sum(cat.Namespace, cat.Name)
	objMeta.Labels[LabelOwnerGeneration] = strconv.FormatInt(cat.Generation, 10)
	if objMeta.Annotations == nil {
		objMeta.Annotations = map[string]string{}
	}
	objMeta.Annotations[AnnotationOwnerIdentifier] = cat.Namespace + "." + cat.Name

	return update, nil
}
