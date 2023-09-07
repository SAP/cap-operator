/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/exp/slices"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

type ProvisioningPayload struct {
	SubscribedSubdomain string `json:"subscribedSubdomain"`
	EventType           string `json:"eventType"`
}

type UpgradePayload struct {
	Tenants      []string `json:"tenants"`
	AutoUnDeploy bool     `json:"autoUndeploy"`
}

type tentantOperationWorkload struct {
	image                   string
	imagePullPolicy         corev1.PullPolicy
	command                 []string
	env                     []corev1.EnvVar
	resources               corev1.ResourceRequirements
	securityContext         *corev1.SecurityContext
	podSecurityContext      *corev1.PodSecurityContext
	backoffLimit            *int32
	ttlSecondsAfterFinished *int32
}

const (
	CAPTenantOperationEventInvalidReference = "InvalidReference"
)

const (
	EnvMTXJobImage            = "MTX_JOB_IMAGE"
	MTXJobImageAllowedPattern = "^ghcr\\.io/sap/cap-operator"
	MTXJobImageDefault        = "ghcr.io/sap/cap-operator/mtx-job"
	EnvIsMTXSEnabled          = "IS_MTXS_ENABLED"
)

type cros struct {
	CAPTenant             *v1alpha1.CAPTenant
	CAPApplication        *v1alpha1.CAPApplication
	CAPApplicationVersion *v1alpha1.CAPApplicationVersion
}

const (
	CAPTenantOperationConditionReasonStepProcessing      string = "StepProcessing"
	CAPTenantOperationConditionReasonStepCompleted       string = "StepCompleted"
	CAPTenantOperationConditionReasonStepFailed          string = "StepFailed"
	CAPTenantOperationConditionReasonStepInitiated       string = "StepInitiated"
	CAPTenantOperationConditionReasonStepProcessingError string = "StepProcessingError"
)

const (
	EventActionCreateJob = "CreateJob"
	EventActionTrackJob  = "TrackJob"
)

func (c *Controller) reconcileCAPTenantOperation(ctx context.Context, item QueueItem, attempts int) (result *ReconcileResult, err error) {
	// cached, err := c.crdInformerFactory.Sme().V1alpha1().CAPTenantOperations().Lister().CAPTenantOperations(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	cached, err := c.crdClient.SmeV1alpha1().CAPTenantOperations(item.ResourceKey.Namespace).Get(ctx, item.ResourceKey.Name, metav1.GetOptions{})

	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	ctop := cached.DeepCopy()

	defer func() {
		if statusErr := c.updateCAPTenantOperationStatus(ctx, ctop); err == nil {
			err = statusErr
		}
	}()

	// prepare owner refs, labels, finalizers
	if update, err := c.prepareCAPTenantOperation(ctop); err != nil {
		return nil, err
	} else if update {
		return c.updateCAPTenantOperation(ctx, ctop, true)
	}

	if !isCROConditionReady(ctop.Status.GenericStatus) {
		return c.reconcileTenantOperationSteps(ctx, ctop)
	} else if ctop.DeletionTimestamp != nil {
		return c.handleCAPTenantOperationDeletion(ctx, ctop)
	}

	return result, err
}

func (c *Controller) updateCAPTenantOperationStatus(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) error {
	if isDeletionImminent(&ctop.ObjectMeta) {
		return nil
	}

	if ctop.DeletionTimestamp != nil {
		// set appropriate state for deletion
		ctop.Status.State = v1alpha1.CAPTenantOperationStateDeleting
	} else if ctop.Status.State == "" {
		// start processing
		ctop.Status.State = v1alpha1.CAPTenantOperationStateProcessing
	}

	ctopUpdated, err := c.crdClient.SmeV1alpha1().CAPTenantOperations(ctop.Namespace).UpdateStatus(ctx, ctop, metav1.UpdateOptions{})
	// update reference to the resource
	if ctopUpdated != nil {
		*ctop = *ctopUpdated
	}
	return err
}

func (c *Controller) prepareCAPTenantOperation(ctop *v1alpha1.CAPTenantOperation) (update bool, err error) {
	// Do nothing when object is deleted
	if ctop.DeletionTimestamp != nil {
		return false, nil
	}
	cat, err := c.getCachedCAPTenant(ctop.Namespace, ctop.Spec.TenantId, true)
	if err != nil {
		msg := fmt.Sprintf("invalid %s reference", v1alpha1.CAPTenantKind)
		c.Event(ctop, nil, corev1.EventTypeWarning, CAPTenantOperationEventInvalidReference, EventActionPrepare, msg)
		return false, err
	}

	// create owner reference - CAPTenant
	if _, ok := getOwnerByKind(ctop.OwnerReferences, v1alpha1.CAPTenantKind); !ok {
		ctop.OwnerReferences = append(ctop.OwnerReferences, *metav1.NewControllerRef(cat, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind)))
		update = true
	}

	if addCAPTenantOperationLabels(ctop, cat) {
		update = true
	}

	if ctop.DeletionTimestamp == nil {
		// set finalizers if not added
		if ctop.Finalizers == nil {
			ctop.Finalizers = []string{}
		}
		if addFinalizer(&ctop.Finalizers, FinalizerCAPTenantOperation) {
			update = true
		}
	}

	return
}

func (c *Controller) getCachedCAPTenantFromOwnerReferences(refs []metav1.OwnerReference, namespace string) (*v1alpha1.CAPTenant, error) {
	// get owning CAPTenant
	owner, ok := getOwnerByKind(refs, v1alpha1.CAPTenantKind)
	if !ok {
		return nil, fmt.Errorf("could not find %s as owner reference", v1alpha1.CAPTenantKind)
	}
	return c.getCachedCAPTenant(namespace, owner.Name, false)
}

func (c *Controller) updateCAPTenantOperation(ctx context.Context, ctop *v1alpha1.CAPTenantOperation, requeue bool) (result *ReconcileResult, err error) {
	var ctopUpdated *v1alpha1.CAPTenantOperation
	ctopUpdated, err = c.crdClient.SmeV1alpha1().CAPTenantOperations(ctop.Namespace).Update(ctx, ctop, metav1.UpdateOptions{})
	// Update reference to the resource
	if ctopUpdated != nil {
		*ctop = *ctopUpdated
	}
	if requeue {
		result = NewReconcileResultWithResource(ResourceCAPTenantOperation, ctop.Name, ctop.Namespace, 1*time.Second)
	}
	return
}

func (c *Controller) handleCAPTenantOperationDeletion(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) (*ReconcileResult, error) {
	// remove finalizer
	update := removeFinalizer(&ctop.Finalizers, FinalizerCAPTenantOperation)
	if update {
		return c.updateCAPTenantOperation(ctx, ctop, false)
	}
	return nil, nil
}

func (c *Controller) reconcileTenantOperationSteps(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) (result *ReconcileResult, err error) {
	/* NOTE REGARDING STEPS:
	 * - Initially the the first step (1) is identified and updated in the status
	 * - the job for the current step is created only in the next pass, which ensures that the current step in the status is always consistent
	 * - when the job for the current step gets completed the current step is incremented in the status (a job created in the subsequent pass)
	 * - the steps are sequentially executed till the end
	 */

	defer func() {
		if err != nil {
			c.Event(ctop, nil, corev1.EventTypeWarning, CAPTenantOperationConditionReasonStepProcessingError, EventActionTrackJob, err.Error())
		}
	}()

	if ctop.Status.CurrentStep == nil { // set initial step
		if len(ctop.Spec.Steps) == 0 {
			err = fmt.Errorf("operation steps missing in %s %s.%s", v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
			ctop.SetStatusWithReadyCondition(v1alpha1.CAPTenantOperationStateFailed, metav1.ConditionTrue, CAPTenantOperationConditionReasonStepProcessingError, err.Error())
			return
		}
		var initStep uint32 = 1
		ctop.SetStatusCurrentStep(&initStep, nil)
		return NewReconcileResultWithResource(ResourceCAPTenantOperation, ctop.Name, ctop.Namespace, 0), nil
	}

	defer func() {
		if err != nil { // set step processing error in status
			ctop.SetStatusWithReadyCondition(ctop.Status.State, metav1.ConditionFalse, CAPTenantOperationConditionReasonStepProcessingError, err.Error())
		}
	}()

	// try to fetch active job
	job, err := c.getActiveCAPTenantOperationJob(ctx, ctop)
	if err != nil {
		return
	}

	if job == nil { // create job for step
		result, err = c.initiateJobForCAPTenantOperationStep(ctx, ctop)
	} else { // track the job
		if ctop.Status.ActiveJob == nil || job.Name != *ctop.Status.ActiveJob { // check whether status is in sync.
			ctop.SetStatusCurrentStep(ctop.Status.CurrentStep, &job.Name)
		}
		result = c.setCAPTenantOperationStatusFromJob(ctop, job)
	}

	return
}

func (c *Controller) getActiveCAPTenantOperationJob(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) (*batchv1.Job, error) {
	// NOTE: read using label selector from the api server (not the cache)
	currentStep := ctop.Spec.Steps[*ctop.Status.CurrentStep-1]
	labelsMap := map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(ctop.Namespace, ctop.Name),
		LabelTenantOperationType: string(ctop.Spec.Operation),
		LabelTenantOperationStep: strconv.FormatInt(int64(*ctop.Status.CurrentStep), 10), // NOTE: step is required to read the job
		LabelWorkloadType:        string(currentStep.Type),                               // NOTE: use step type and not workload type as TenantOperation could be derived from CAP
		LabelWorkloadName:        currentStep.Name,
	}
	selector := labels.SelectorFromSet(labelsMap)
	jobs, err := c.kubeClient.BatchV1().Jobs(ctop.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}

	switch len(jobs.Items) {
	case 0:
		return nil, nil
	case 1:
		return &jobs.Items[0], nil
	default:
		return nil, fmt.Errorf("multiple jobs exist for step %v of %s %s.%s", *ctop.Status.CurrentStep, v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
	}
}

func (c *Controller) setCAPTenantOperationStatusFromJob(ctop *v1alpha1.CAPTenantOperation, job *batchv1.Job) (result *ReconcileResult) {
	var requeueAfter time.Duration = 1 * time.Second
	status := struct {
		state            v1alpha1.CAPTenantOperationState
		conditionReason  string
		conditionStatus  metav1.ConditionStatus
		conditionMessage string
		eventType        string
	}{}

	isFinalStep := false
	if *ctop.Status.CurrentStep == uint32(len(ctop.Spec.Steps)) {
		isFinalStep = true
	}

	processStepCompletion := func() {
		status.conditionReason = CAPTenantOperationConditionReasonStepCompleted
		if isFinalStep {
			status.state = v1alpha1.CAPTenantOperationStateCompleted
			status.conditionStatus = metav1.ConditionTrue
			ctop.SetStatusCurrentStep(nil, nil)
		} else {
			status.state = v1alpha1.CAPTenantOperationStateProcessing
			status.conditionStatus = metav1.ConditionFalse
			nxtStep := *ctop.Status.CurrentStep + 1
			ctop.SetStatusCurrentStep(&nxtStep, nil)
		}
	}

	jobState := getJobState(job)
	switch jobState {
	case JobStateComplete:
		status.conditionMessage = fmt.Sprintf("step %v/%v : job %s.%s completed", *ctop.Status.CurrentStep, len(ctop.Spec.Steps), job.Namespace, job.Name)
		status.eventType = corev1.EventTypeNormal
		processStepCompletion()
	case JobStateFailed:
		status.conditionMessage = fmt.Sprintf("step %v/%v : job %s.%s failed", *ctop.Status.CurrentStep, len(ctop.Spec.Steps), job.Namespace, job.Name)
		status.eventType = corev1.EventTypeWarning
		if step := ctop.Spec.Steps[*ctop.Status.CurrentStep-1]; step.ContinueOnFailure {
			status.conditionMessage = status.conditionMessage + "; continuing operation"
			processStepCompletion() // NOTE: condition.reason needs to be set to StepCompleted in this case, as this is looked up by the CAPTenant
		} else {
			status.conditionReason = CAPTenantOperationConditionReasonStepFailed
			status.state = v1alpha1.CAPTenantOperationStateFailed
			status.conditionStatus = metav1.ConditionTrue
			ctop.SetStatusCurrentStep(nil, nil)
		}
	case JobStateProcessing:
		status.conditionReason = CAPTenantOperationConditionReasonStepProcessing
		status.conditionMessage = fmt.Sprintf("step %v/%v : waiting for job %s.%s", *ctop.Status.CurrentStep, len(ctop.Spec.Steps), job.Namespace, job.Name)
		status.state = v1alpha1.CAPTenantOperationStateProcessing
		status.conditionStatus = metav1.ConditionFalse
		requeueAfter = 15 * time.Second
	}

	ctop.SetStatusWithReadyCondition(status.state, status.conditionStatus, status.conditionReason, status.conditionMessage)
	if status.eventType != "" {
		c.Event(ctop, job, status.eventType, status.conditionReason, EventActionTrackJob, status.conditionMessage)
	}

	return NewReconcileResultWithResource(ResourceCAPTenantOperation, ctop.Name, ctop.Namespace, requeueAfter)
}

func (c *Controller) getCAPResourcesFromCAPTenantOperation(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) (*cros, error) {
	// get owning CAPTenant
	cat, err := c.getCachedCAPTenantFromOwnerReferences(ctop.OwnerReferences, ctop.Namespace)
	if err != nil {
		return nil, err
	}

	// get owning CAPApplication
	owner, ok := getOwnerByKind(cat.OwnerReferences, v1alpha1.CAPApplicationKind)
	if !ok {
		return nil, fmt.Errorf("%s could not be identified for %s %s.%s", v1alpha1.CAPApplicationKind, v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
	}
	ca, err := c.getCachedCAPApplication(cat.Namespace, owner.Name)
	if err != nil {
		return nil, err
	}

	// get specified CAPApplicationVersion
	cav, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions(ca.Namespace).Get(ctx, ctop.Spec.CAPApplicationVersionInstance, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	// verify status of CAPApplicationVersion
	if !isCROConditionReady(cav.Status.GenericStatus) {
		return nil, fmt.Errorf("%s %s is not %s to be used in %s %s.%s", v1alpha1.CAPApplicationVersionKind, cav.Name, v1alpha1.CAPApplicationVersionStateReady, v1alpha1.CAPTenantOperationKind, ctop.Namespace, ctop.Name)
	}

	return &cros{
		CAPApplication:        ca,
		CAPTenant:             cat,
		CAPApplicationVersion: cav,
	}, nil
}

func (c *Controller) initiateJobForCAPTenantOperationStep(ctx context.Context, ctop *v1alpha1.CAPTenantOperation) (result *ReconcileResult, err error) {
	relatedResources, err := c.getCAPResourcesFromCAPTenantOperation(ctx, ctop)
	if err != nil {
		return nil, err
	}

	// get workload
	step := ctop.Spec.Steps[*ctop.Status.CurrentStep-1]
	workload := getWorkloadByName(step.Name, relatedResources.CAPApplicationVersion)
	if workload == nil {
		return nil, fmt.Errorf("could not find workload %s in %s %s.%s", step.Name, v1alpha1.CAPApplicationVersionKind, relatedResources.CAPApplicationVersion.Namespace, relatedResources.CAPApplicationVersion.Name)
	}

	// create VCAP secret from consumed BTP services
	consumedServiceInfos := getConsumedServiceInfos(getConsumedServiceMap(workload.ConsumedBTPServices), relatedResources.CAPApplication.Spec.BTP.Services)
	vcapSecretName, err := createVCAPSecret(ctop.Name+"-"+strings.ToLower(workload.Name), ctop.Namespace, *metav1.NewControllerRef(ctop, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantOperationKind)), consumedServiceInfos, c.kubeClient)
	if err != nil {
		return nil, err
	}

	annotations := copyMaps(workload.Annotations, map[string]string{
		AnnotationIstioSidecarInject:       "false",
		AnnotationBTPApplicationIdentifier: relatedResources.CAPApplication.Spec.GlobalAccountId + "." + relatedResources.CAPApplication.Spec.BTPAppName,
		AnnotationOwnerIdentifier:          ctop.Namespace + "." + ctop.Name,
	})

	labels := copyMaps(workload.Labels, map[string]string{
		App:                               relatedResources.CAPApplication.Spec.BTPAppName,
		LabelBTPApplicationIdentifierHash: sha1Sum(relatedResources.CAPApplication.Spec.GlobalAccountId, relatedResources.CAPApplication.Spec.BTPAppName),
		LabelOwnerIdentifierHash:          sha1Sum(ctop.Namespace, ctop.Name),
		LabelOwnerGeneration:              strconv.FormatInt(ctop.Generation, 10),
		LabelTenantOperationType:          string(ctop.Spec.Operation),
		LabelTenantOperationStep:          strconv.FormatInt(int64(*ctop.Status.CurrentStep), 10), // NOTE: step is required to read the job
		LabelWorkloadName:                 step.Name,
		LabelWorkloadType:                 string(step.Type), // NOTE: use step type and not workload type as TenantOperation could be derived from CAP
		LabelResourceCategory:             CategoryWorkload,
	})

	params := &jobCreateParams{
		namePrefix:        relatedResources.CAPTenant.Name + "-" + workload.Name + "-",
		labels:            labels,
		annotations:       annotations,
		envFromVCAPSecret: getEnvFrom(vcapSecretName),
		imagePullSecrets:  convertToLocalObjectReferences(relatedResources.CAPApplicationVersion.Spec.RegistrySecrets),
		version:           relatedResources.CAPApplicationVersion.Spec.Version,
	}

	var job *batchv1.Job
	if ctop.Spec.Steps[*ctop.Status.CurrentStep-1].Type == v1alpha1.JobTenantOperation {
		if params.xsuaaInstanceName, err = getXSUAAInstanceName(consumedServiceInfos, relatedResources, c.kubeClient); err != nil {
			return
		}
		job, err = c.createTenantOperationJob(ctx, ctop, workload, params)
	} else { // custom tenant operation
		job, err = c.createCustomTenantOperationJob(ctx, ctop, workload, params)
	}
	if err != nil {
		return
	}

	msg := fmt.Sprintf("step %v/%v : job %s.%s created", *ctop.Status.CurrentStep, len(ctop.Spec.Steps), job.Namespace, job.Name)
	ctop.SetStatusWithReadyCondition(v1alpha1.CAPTenantOperationStateProcessing, metav1.ConditionFalse, CAPTenantOperationConditionReasonStepInitiated, msg)
	ctop.SetStatusCurrentStep(ctop.Status.CurrentStep, &job.Name)
	c.Event(ctop, job, corev1.EventTypeNormal, CAPTenantOperationConditionReasonStepInitiated, EventActionCreateJob, msg)

	return NewReconcileResultWithResource(ResourceCAPTenantOperation, ctop.Name, ctop.Namespace, 15*time.Second), nil
}

type jobCreateParams struct {
	namePrefix        string
	labels            map[string]string
	annotations       map[string]string
	envFromVCAPSecret []corev1.EnvFromSource
	imagePullSecrets  []corev1.LocalObjectReference
	version           string
	xsuaaInstanceName string
}

func (c *Controller) createTenantOperationJob(ctx context.Context, ctop *v1alpha1.CAPTenantOperation, workload *v1alpha1.WorkloadDetails, params *jobCreateParams) (*batchv1.Job, error) {
	// prepare payload request
	var (
		payload []byte
		err     error
	)
	if ctop.Spec.Operation == v1alpha1.CAPTenantOperationTypeProvisioning {
		payload, err = json.Marshal(ProvisioningPayload{SubscribedSubdomain: ctop.Spec.SubDomain, EventType: "CREATE"})
	} else if ctop.Spec.Operation == v1alpha1.CAPTenantOperationTypeUpgrade {
		payload, err = json.Marshal(UpgradePayload{Tenants: []string{ctop.Spec.TenantId}, AutoUnDeploy: true})
	} else { // deprovisioning
		payload, err = json.Marshal(struct{}{})
	}
	if err != nil {
		return nil, err
	}

	derivedWorkload := deriveWorkloadForTenantOperation(workload)

	// create job for tenant operation (provisioning / upgrade / deprovisioning)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    params.namePrefix, // generate name for each step
			Namespace:       ctop.Namespace,
			Labels:          params.labels,
			Annotations:     params.annotations,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ctop, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantOperationKind))},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            derivedWorkload.backoffLimit,
			TTLSecondsAfterFinished: derivedWorkload.ttlSecondsAfterFinished,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      params.labels,
					Annotations: params.annotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:    corev1.RestartPolicyNever,
					ImagePullSecrets: params.imagePullSecrets,
					Containers:       getContainers(payload, ctop, derivedWorkload, workload, params),
					SecurityContext:  derivedWorkload.podSecurityContext,
				},
			},
		},
	}

	return c.kubeClient.BatchV1().Jobs(ctop.Namespace).Create(ctx, job, metav1.CreateOptions{})
}

func isMTXSDisabled(envVars []corev1.EnvVar) bool {
	return slices.ContainsFunc(envVars, func(env corev1.EnvVar) bool { return env.Name == EnvIsMTXSEnabled && env.Value == "false" })
}

func getContainers(payload []byte, ctop *v1alpha1.CAPTenantOperation, derivedWorkload tentantOperationWorkload, workload *v1alpha1.WorkloadDetails, params *jobCreateParams) []corev1.Container {
	if !isMTXSDisabled(derivedWorkload.env) {
		var operation string
		container := &corev1.Container{
			Name:            workload.Name,
			Image:           derivedWorkload.image,
			ImagePullPolicy: derivedWorkload.imagePullPolicy,
			Env: append([]corev1.EnvVar{
				{Name: EnvCAPOpAppVersion, Value: params.version}, {Name: EnvCAPOpTenantID, Value: ctop.Spec.TenantId}, {Name: EnvCAPOpTenantOperation, Value: string(ctop.Spec.Operation)}, {Name: EnvCAPOpTenantSubDomain, Value: string(ctop.Spec.SubDomain)},
			}, derivedWorkload.env...),
			EnvFrom:         params.envFromVCAPSecret,
			Resources:       derivedWorkload.resources,
			SecurityContext: derivedWorkload.securityContext,
		}

		if ctop.Spec.Operation == v1alpha1.CAPTenantOperationTypeProvisioning {
			operation = "subscribe"
		} else if ctop.Spec.Operation == v1alpha1.CAPTenantOperationTypeUpgrade {
			operation = "upgrade"
		} else { // deprovisioning
			operation = "unsubscribe"
		}

		if derivedWorkload.command != nil {
			container.Command = derivedWorkload.command
		} else {
			container.Command = []string{"node", "./node_modules/@sap/cds-mtxs/bin/cds-mtx", operation, ctop.Spec.TenantId}
		}

		return append([]corev1.Container{}, *container)
	}

	return []corev1.Container{
		{
			Name:  "trigger", // TODO: get rid of this --> hopefully with mtxs cli where we start a single container image
			Image: getMTXJobImage(),
			Env: []corev1.EnvVar{
				{Name: "WAIT_FOR_SIDECAR", Value: "false"},
				{Name: "XSUAA_INSTANCE_NAME", Value: params.xsuaaInstanceName},
				{Name: "MTX_SERVICE_URL", Value: "http://localhost:" + strconv.Itoa(defaultServerPort)},
				{Name: "MTX_REQUEST_TYPE", Value: string(ctop.Spec.Operation)},
				{Name: "MTX_TENANT_ID", Value: ctop.Spec.TenantId},
				{Name: "MTX_REQUEST_PAYLOAD", Value: string(payload)},
			},
			EnvFrom: params.envFromVCAPSecret,
		},
		{
			Name:            workload.Name,
			Image:           derivedWorkload.image,
			ImagePullPolicy: derivedWorkload.imagePullPolicy,
			Env: append([]corev1.EnvVar{
				{Name: EnvCAPOpAppVersion, Value: params.version}, {Name: EnvCAPOpTenantID, Value: ctop.Spec.TenantId}, {Name: EnvCAPOpTenantOperation, Value: string(ctop.Spec.Operation)}, {Name: EnvCAPOpTenantSubDomain, Value: string(ctop.Spec.SubDomain)},
			}, derivedWorkload.env...),
			EnvFrom:         params.envFromVCAPSecret,
			Resources:       derivedWorkload.resources,
			SecurityContext: derivedWorkload.securityContext,
			Command:         []string{"/bin/sh", "-c"},
			Args:            []string{"node ./node_modules/@sap/cds/bin/cds run & nc -lv -s localhost -p 8080"},
		},
	}
}

func deriveWorkloadForTenantOperation(workload *v1alpha1.WorkloadDetails) tentantOperationWorkload {
	result := tentantOperationWorkload{}
	if workload.JobDefinition == nil {
		// this must be a reference to CAP workload
		result.image = workload.DeploymentDefinition.Image
		result.imagePullPolicy = workload.DeploymentDefinition.ImagePullPolicy
		result.env = workload.DeploymentDefinition.Env
		result.resources = workload.DeploymentDefinition.Resources
		result.backoffLimit = &backoffLimitValue
		result.ttlSecondsAfterFinished = &tTLSecondsAfterFinishedValue
		result.securityContext = workload.DeploymentDefinition.SecurityContext
		result.podSecurityContext = workload.DeploymentDefinition.PodSecurityContext
	} else {
		// use job definition
		result.image = workload.JobDefinition.Image
		result.imagePullPolicy = workload.JobDefinition.ImagePullPolicy
		result.command = workload.JobDefinition.Command
		result.env = workload.JobDefinition.Env
		result.resources = workload.JobDefinition.Resources
		result.securityContext = workload.JobDefinition.SecurityContext
		result.podSecurityContext = workload.JobDefinition.PodSecurityContext
		if workload.JobDefinition.BackoffLimit != nil {
			result.backoffLimit = workload.JobDefinition.BackoffLimit
		}
		if workload.JobDefinition.TTLSecondsAfterFinished != nil {
			result.ttlSecondsAfterFinished = workload.JobDefinition.TTLSecondsAfterFinished
		}
	}
	return result
}

func (c *Controller) createCustomTenantOperationJob(ctx context.Context, ctop *v1alpha1.CAPTenantOperation, workload *v1alpha1.WorkloadDetails, params *jobCreateParams) (*batchv1.Job, error) {
	// create job for custom tenant operation
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    params.namePrefix, // generate name for each step
			Namespace:       ctop.Namespace,
			Labels:          params.labels,
			Annotations:     params.annotations,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ctop, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantOperationKind))},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            workload.JobDefinition.BackoffLimit,
			TTLSecondsAfterFinished: workload.JobDefinition.TTLSecondsAfterFinished,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      params.labels,
					Annotations: params.annotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:    corev1.RestartPolicyNever,
					SecurityContext:  workload.JobDefinition.PodSecurityContext,
					ImagePullSecrets: params.imagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:            workload.Name,
							Image:           workload.JobDefinition.Image,
							ImagePullPolicy: workload.JobDefinition.ImagePullPolicy,
							Env: append([]corev1.EnvVar{
								{Name: EnvCAPOpAppVersion, Value: params.version}, {Name: EnvCAPOpTenantID, Value: ctop.Spec.TenantId}, {Name: EnvCAPOpTenantOperation, Value: string(ctop.Spec.Operation)}, {Name: EnvCAPOpTenantSubDomain, Value: string(ctop.Spec.SubDomain)},
							}, workload.JobDefinition.Env...),
							EnvFrom:         params.envFromVCAPSecret,
							Command:         workload.JobDefinition.Command,
							Resources:       workload.JobDefinition.Resources,
							SecurityContext: workload.JobDefinition.SecurityContext,
						},
					},
				},
			},
		},
	}

	return c.kubeClient.BatchV1().Jobs(ctop.Namespace).Create(ctx, job, metav1.CreateOptions{})
}

func getMTXJobImage() string {
	mtxJobImageUri := os.Getenv(EnvMTXJobImage)
	allowedUri, _ := regexp.MatchString(MTXJobImageAllowedPattern, mtxJobImageUri)
	if !allowedUri {
		klog.Warning("MTX Job Image URI '", mtxJobImageUri, "' not given in environment, or not allowed. Falling back to default.")
		mtxJobImageUri = MTXJobImageDefault
	}

	return mtxJobImageUri
}

func getXSUAAInstanceName(consumedServiceInfos []v1alpha1.ServiceInfo, relatedResources *cros, kubeClient kubernetes.Interface) (string, error) {
	info := util.GetXSUAAInfo(consumedServiceInfos, relatedResources.CAPApplication)
	if info.Secret == "" {
		return "", errors.New("missing XSUAA service information")
	}
	entry, err := util.CreateVCAPEntryFromSecret(info, relatedResources.CAPApplication.Namespace, kubeClient)
	if err != nil {
		return "", err
	}
	return entry["name"].(string), nil
}

func addCAPTenantOperationLabels(ctop *v1alpha1.CAPTenantOperation, cat *v1alpha1.CAPTenant) (updated bool) {
	appMetadata := appMetadataIdentifiers{
		ownerInfo: &ownerInfo{
			ownerNamespace:  cat.Namespace,
			ownerName:       cat.Name,
			ownerGeneration: cat.Generation,
		},
	}
	if updateLabelAnnotationMetadata(&ctop.ObjectMeta, &appMetadata) {
		updated = true
	}

	if _, ok := ctop.Labels[LabelTenantOperationType]; !ok {
		ctop.Labels[LabelTenantOperationType] = string(ctop.Spec.Operation)
		if ctop.Spec.Operation == v1alpha1.CAPTenantOperationTypeUpgrade {
			ctop.Labels[LabelCAVVersion] = cat.Spec.Version
		}
		updated = true
	}
	return updated
}
