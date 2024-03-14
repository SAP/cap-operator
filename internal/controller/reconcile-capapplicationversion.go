/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
)

const (
	App = "app"
)

const (
	CategoryWorkload = "Workload"
	CategoryService  = "Service"
)

const (
	defaultServerPort = 4004
	defaultRouterPort = 5000
)

var trueVal = true

type DeploymentParameters struct {
	CA              *v1alpha1.CAPApplication
	CAV             *v1alpha1.CAPApplicationVersion
	OwnerRef        *metav1.OwnerReference
	WorkloadDetails v1alpha1.WorkloadDetails
	VCAPSecretName  string
}

func (c *Controller) reconcileCAPApplicationVersion(ctx context.Context, item QueueItem, attempts int) (*ReconcileResult, error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister()
	cached, err := lister.CAPApplicationVersions(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	cav := cached.DeepCopy()

	// prepare owner refs, labels, finalizers
	if update, err := c.prepareCAPApplicationVersion(ctx, cav); err != nil {
		return nil, err
	} else if update {
		err := c.updateCAPApplicationVersion(ctx, cav)
		if err != nil {
			return nil, err
		}
	}

	// Handle Deletion
	if cav.DeletionTimestamp != nil {
		return c.deleteCAPApplicationVersion(ctx, cav)
	}

	return c.handleCAPApplicationVersion(ctx, cav)
}

func (c *Controller) updateCAPApplicationVersionStatus(ctx context.Context, cav *v1alpha1.CAPApplicationVersion, state v1alpha1.CAPApplicationVersionState, condition metav1.Condition) error {
	cav.SetStatusWithReadyCondition(state, condition.Status, condition.Reason, condition.Message)

	cavUpdated, statusErr := c.crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).UpdateStatus(ctx, cav, metav1.UpdateOptions{})
	// Update reference to the resource
	if cavUpdated != nil {
		*cav = *cavUpdated
	}
	if statusErr != nil {
		klog.ErrorS(statusErr, "could not update status of application version", "namespace", cav.Namespace, v1alpha1.CAPApplicationVersionKind, cav)
	}

	return statusErr
}

func (c *Controller) updateCAPApplicationVersion(ctx context.Context, cav *v1alpha1.CAPApplicationVersion) error {
	cavUpdated, err := c.crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).Update(ctx, cav, metav1.UpdateOptions{})
	// Update reference to the resource
	if cavUpdated != nil {
		*cav = *cavUpdated
	}
	return err
}

func (c *Controller) handleCAPApplicationVersion(ctx context.Context, cav *v1alpha1.CAPApplicationVersion) (*ReconcileResult, error) {
	ca, _ := c.getCachedCAPApplication(cav.Namespace, cav.Spec.CAPApplicationInstance)

	// Check for valid secrets
	err := c.checkSecretsExist(ca.Spec.BTP.Services, ca.Namespace)

	if err != nil {
		// Requeue after 10s to check if secrets exist
		return NewReconcileResultWithResource(ResourceCAPApplicationVersion, cav.Name, cav.Namespace, 10*time.Second), c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateProcessing, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "WaitingForSecrets"})
	}

	// If Valid secrets exists proceed with processing deployment
	var statusErr error
	switch cav.Status.State {
	case "":
		statusErr = c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateProcessing, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ReadyForProcessing"})
	case v1alpha1.CAPApplicationVersionStateError:
		var errorCondition metav1.Condition
		if len(cav.Status.Conditions) > 0 {
			errorCondition = *cav.Status.Conditions[0].DeepCopy() // keep the error condition while re-processing
		} else {
			errorCondition = metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "RetryProcessing"}
		}
		statusErr = c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateProcessing, errorCondition)
	}

	if statusErr != nil {
		return nil, statusErr
	}

	return c.processDeployments(ctx, ca, cav)
}

func (c *Controller) processDeployments(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) (*ReconcileResult, error) {
	// TODO: handle create/update of individual deployments/jobs (so far these are just created and never updated, as we expect secrets don't change!)

	// Handle Content job
	err := c.handleContentDeployJob(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInContentDeploymentJob", Message: err.Error()})
		return nil, err
	}

	// Create AppRouter Deployment
	err = c.updateApprouterDeployment(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInAppRouterDeployment", Message: err.Error()})
		return nil, err
	}

	// Create Server Deployment
	err = c.updateServerDeployment(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInServerDeployment", Message: err.Error()})
		return nil, err
	}

	// Create All Services
	err = c.updateServices(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInServerService", Message: err.Error()})
		return nil, err
	}

	// Create Additional Deployments
	err = c.updateAdditionalDeployment(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInJobWorkerDeployment", Message: err.Error()})
		return nil, err
	}

	// Create NetworkPolicy
	err = c.updateNetworkPolicies(ca, cav)
	if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInNetworkPolicy", Message: err.Error()})
		return nil, err
	}

	// TODO: Checks for issues with Deployment(s)!
	// Check for status of contentWorkloads
	processing, err := c.checkContentWorkloadStatus(ctx, cav)
	if processing {
		return NewReconcileResultWithResource(ResourceCAPApplicationVersion, cav.Name, cav.Namespace, 0), nil
	} else if err != nil {
		c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateError, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ErrorInWorkloadStatus", Message: err.Error()})
		return nil, err
	}

	// TODO: wait until the deployments are actually "Ready"!
	return nil, c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateReady, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "True", Reason: "CreatedDeployments"})
}

func getContentJobName(contentJobWorkloadName string, cav *v1alpha1.CAPApplicationVersion) string {
	if cav.Spec.ContentJobs == nil { // for backward compactibility as there could be existing jobs in the clusters with old names
		return cav.Name + "-" + strings.ToLower(string(v1alpha1.JobContent))
	}
	return cav.Name + "-" + contentJobWorkloadName + "-" + strings.ToLower(string(v1alpha1.JobContent))
}

func getNextContentJob(cav *v1alpha1.CAPApplicationVersion) *v1alpha1.WorkloadDetails {

	// If the previous job failed, we should not trigger the next job
	if len(cav.Status.Conditions) > 0 && cav.Status.Conditions[0].Reason == "ErrorInWorkloadStatus" {
		return nil
	}

	if cav.Spec.ContentJobs == nil {
		contentJobWorkload := getRelevantJob(v1alpha1.JobContent, cav)
		if contentJobWorkload != nil && !cav.CheckFinishedJobs(getContentJobName(contentJobWorkload.Name, cav)) {
			return contentJobWorkload
		}
		return nil
	}

	for _, name := range cav.Spec.ContentJobs {
		if !cav.CheckFinishedJobs(getContentJobName(name, cav)) {
			return getWorkloadByName(name, cav)
		}
	}
	return nil
}

// #region Content Deploy Job
func (c *Controller) handleContentDeployJob(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {

	workload := getNextContentJob(cav)
	// All jobs executed --> exit
	if workload == nil {
		return nil
	}

	if res := validateEnv(workload.JobDefinition.Env, restrictedEnvNames); res != "" {
		return errorEnv(workload.Name, res)
	}

	var vcapSecretName string
	jobName := getContentJobName(workload.Name, cav)

	// Get the contentDeploy job with the name expected for this CAV instance
	contentDeployJob, err := c.kubeInformerFactory.Batch().V1().Jobs().Lister().Jobs(cav.Namespace).Get(jobName)
	// If the resource doesn't exist, we'll create it
	if k8sErrors.IsNotFound(err) {
		// Get ServiceInfos for consumed BTP services
		consumedServiceInfos := getConsumedServiceInfos(getConsumedServiceMap(workload.ConsumedBTPServices), ca.Spec.BTP.Services)

		// Create ownerRef to CAV
		ownerRef := *metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind))

		// Get VCAP secret name
		vcapSecretName, err = createVCAPSecret(jobName, cav.Namespace, ownerRef, consumedServiceInfos, c.kubeClient)

		if err == nil {
			contentDeployJob, err = c.kubeClient.BatchV1().Jobs(cav.Namespace).Create(context.TODO(), newContentDeploymentJob(ca, cav, workload, ownerRef, vcapSecretName), metav1.CreateOptions{})
		}
	}

	return doChecks(err, contentDeployJob, cav, workload.Name)
}

// newContentDeploymentJob creates a Content Deployment Job for the CAV resource. It also sets the appropriate OwnerReferences.
func newContentDeploymentJob(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, workload *v1alpha1.WorkloadDetails, ownerRef metav1.OwnerReference, vcapSecretName string) *batchv1.Job {
	labels := copyMaps(workload.Labels, map[string]string{
		LabelDisableKarydia: "true",
	})

	annotations := copyMaps(workload.Annotations, map[string]string{
		AnnotationIstioSidecarInject: "false",
	})

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getContentJobName(workload.Name, cav),
			Namespace:   cav.Namespace,
			Annotations: workload.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				ownerRef,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            workload.JobDefinition.BackoffLimit,
			TTLSecondsAfterFinished: workload.JobDefinition.TTLSecondsAfterFinished,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            workload.Name,
							Image:           workload.JobDefinition.Image,
							ImagePullPolicy: workload.JobDefinition.ImagePullPolicy,
							Command:         workload.JobDefinition.Command,
							Env: append([]corev1.EnvVar{
								{Name: EnvCAPOpAppVersion, Value: cav.Spec.Version},
							}, workload.JobDefinition.Env...),
							EnvFrom:         getEnvFrom(vcapSecretName),
							VolumeMounts:    workload.JobDefinition.VolumeMounts,
							Resources:       workload.JobDefinition.Resources,
							SecurityContext: workload.JobDefinition.SecurityContext,
						},
					},
					SecurityContext:           workload.JobDefinition.PodSecurityContext,
					ServiceAccountName:        workload.JobDefinition.ServiceAccountName,
					Volumes:                   workload.JobDefinition.Volumes,
					ImagePullSecrets:          convertToLocalObjectReferences(cav.Spec.RegistrySecrets),
					RestartPolicy:             corev1.RestartPolicyOnFailure,
					NodeSelector:              workload.JobDefinition.NodeSelector,
					NodeName:                  workload.JobDefinition.NodeName,
					PriorityClassName:         workload.JobDefinition.PriorityClassName,
					Affinity:                  workload.JobDefinition.Affinity,
					TopologySpreadConstraints: workload.JobDefinition.TopologySpreadConstraints,
					Tolerations:               workload.JobDefinition.Tolerations,
				},
			},
		},
	}
}

//#endregion

// #region Server
func (c *Controller) updateServerDeployment(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	serverWorkloads := getDeployments(v1alpha1.DeploymentCAP, cav)
	for _, serverWorkload := range serverWorkloads {
		err := c.updateDeployment(ca, cav, &serverWorkload)
		if err != nil {
			return err
		}
	}
	return nil
}

//#endregion

// #region AppRouter
func (c *Controller) updateApprouterDeployment(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	routerWorkload := getRelevantDeployment(v1alpha1.DeploymentRouter, cav)
	return c.updateDeployment(ca, cav, routerWorkload)
}

//#endregion

// #region JobWorker
func (c *Controller) updateAdditionalDeployment(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	additionalWorkloads := getDeployments(v1alpha1.DeploymentAdditional, cav)
	for _, workload := range additionalWorkloads {
		err := c.updateDeployment(ca, cav, &workload)
		if err != nil {
			return err
		}
	}
	return nil
}

//#endregion

// #region Service
func (c *Controller) updateServices(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	workloadServicePortInfos := getRelevantServicePortInfo(cav)
	for _, workloadServicePortInfo := range workloadServicePortInfos {
		// Get the Service with the name specified in CustomDeployment.spec
		service, err := c.kubeClient.CoreV1().Services(cav.Namespace).Get(context.TODO(), workloadServicePortInfo.WorkloadName+ServiceSuffix, metav1.GetOptions{})
		// If the resource doesn't exist, we'll create it
		if k8sErrors.IsNotFound(err) {
			service, err = c.kubeClient.CoreV1().Services(cav.Namespace).Create(context.TODO(), newService(ca, cav, workloadServicePortInfo), metav1.CreateOptions{})
		}

		err = doChecks(err, service, cav, workloadServicePortInfo.WorkloadName+ServiceSuffix)
		if err != nil {
			return err
		}
	}
	return nil
}

// newService creates a new Service for a CAV resource. It also sets the appropriate OwnerReferences.
func newService(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, workloadServicePortInfo servicePortInfo) *corev1.Service {
	var ports []corev1.ServicePort

	for _, port := range workloadServicePortInfo.Ports {
		ports = append(ports, corev1.ServicePort{Name: port.Name, Port: port.Port, AppProtocol: port.AppProtocol})
	}

	matchlabels := getLabels(ca, cav, CategoryWorkload, workloadServicePortInfo.DeploymentType, workloadServicePortInfo.WorkloadName, false)

	workload := getWorkloadByName(workloadServicePortInfo.WorkloadName[len(cav.Name)+1:], cav)

	annotations := copyMaps(workload.Annotations, getAnnotations(ca, cav, true))

	labels := copyMaps(workload.Labels, getLabels(ca, cav, CategoryService, workloadServicePortInfo.DeploymentType, workloadServicePortInfo.WorkloadName+ServiceSuffix, true))

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        workloadServicePortInfo.WorkloadName + ServiceSuffix,
			Namespace:   cav.Namespace,
			Labels:      labels,
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind)),
			},
		},
		Spec: corev1.ServiceSpec{
			Ports:    ports,
			Selector: matchlabels,
		},
	}
}

// #endregion Service

// #region NetworkPolicy
func (c *Controller) updateNetworkPolicies(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	var (
		spec networkingv1.NetworkPolicySpec
		err  error
	)

	// The app pod specific NetworkPolicy
	spec = getAppPodNetworkPolicySpec(ca, cav)
	err = c.createNetworkPolicy(cav.Name, spec, cav)
	if err != nil {
		return err
	}

	// The app ingress (to router) NetworkPolicy
	spec = getAppIngressNetworkPolicySpec(ca, cav)
	err = c.createNetworkPolicy(cav.Name+"--in", spec, cav)
	if err != nil {
		return err
	}

	// (Tech)Port specific network policy (just clusterWide for now)
	// Get all the relevant service info (that includes ports exposed clusterwide)
	workloadServicePortInfos := getRelevantServicePortInfo(cav)
	for _, workloadServicePortInfo := range workloadServicePortInfos {
		if len(workloadServicePortInfo.ClusterPorts) > 0 {
			// Create a network policy for the workload if at least 1 clusterwide exposed port exists.
			spec = getPortSpecificNetworkPolicySpec(workloadServicePortInfo, ca, cav)
			err = c.createNetworkPolicy(workloadServicePortInfo.WorkloadName, spec, cav)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// check and create a new NetworkPolicy for the given workload/CAV resource. It also sets the appropriate OwnerReferences.
func (c *Controller) createNetworkPolicy(name string, spec networkingv1.NetworkPolicySpec, cav *v1alpha1.CAPApplicationVersion) error {
	networkPolicy, err := c.kubeClient.NetworkingV1().NetworkPolicies(cav.Namespace).Get(context.TODO(), name, metav1.GetOptions{})
	// If the resource doesn't exist, we'll create it
	if k8sErrors.IsNotFound(err) {
		networkPolicy, err = c.kubeClient.NetworkingV1().NetworkPolicies(cav.Namespace).Create(context.TODO(), &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: cav.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind)),
				},
			},
			Spec: spec,
		}, metav1.CreateOptions{})
	}
	return doChecks(err, networkPolicy, cav, "NetworkPolicy")
}

func getAppPodNetworkPolicySpec(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) networkingv1.NetworkPolicySpec {
	return networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{
				// Enable communication across all workload pods with the same version
				{
					PodSelector: &metav1.LabelSelector{MatchLabels: getLabels(ca, cav, CategoryWorkload, "", "", false)},
				},
			},
		}},
		// Target all workloads of the app
		PodSelector: metav1.LabelSelector{MatchLabels: getLabels(ca, cav, CategoryWorkload, "", "", false)},
	}
}

func getAppIngressNetworkPolicySpec(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) networkingv1.NetworkPolicySpec {
	return networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{
				// Enable ingress traffic to the router via istio-ingress gateway
				{
					NamespaceSelector: &metav1.LabelSelector{},
					PodSelector:       &metav1.LabelSelector{MatchLabels: getIngressGatewayLabels(ca)},
				},
			},
		}},
		// Target all workloads of the app
		PodSelector: metav1.LabelSelector{MatchLabels: getLabels(ca, cav, CategoryWorkload, string(v1alpha1.DeploymentRouter), "", false)},
	}
}

func getPortSpecificNetworkPolicySpec(workloadServicePortInfo servicePortInfo, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) networkingv1.NetworkPolicySpec {
	ports := []networkingv1.NetworkPolicyPort{}
	for _, port := range workloadServicePortInfo.ClusterPorts {
		ports = append(ports, networkingv1.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: port}})
	}
	return networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			Ports: ports,
			From: []networkingv1.NetworkPolicyPeer{
				// Enable ingress traffic to these ports from any pod in the cluster
				{
					NamespaceSelector: &metav1.LabelSelector{},
					PodSelector:       &metav1.LabelSelector{},
				},
			},
		}},
		// Target the relevant workload whose port(s) needs to be exposed cluster wide
		PodSelector: metav1.LabelSelector{MatchLabels: getLabels(ca, cav, CategoryWorkload, workloadServicePortInfo.DeploymentType, workloadServicePortInfo.WorkloadName, false)},
	}
}

// #endregion NetworkPolicy

// #region Deployments

func (c *Controller) updateDeployment(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, workload *v1alpha1.WorkloadDetails) error {
	if res := validateEnv(workload.DeploymentDefinition.Env, restrictedEnvNames); res != "" {
		return errorEnv(workload.Name, res)
	}

	var vcapSecretName string
	deploymentName := cav.Name + "-" + strings.ToLower(string(workload.Name))
	// Get the workloadDeployment with the name specified in CustomDeployment.spec
	workloadDeployment, err := c.kubeClient.AppsV1().Deployments(cav.Namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	// If the resource doesn't exist, we'll create it
	if k8sErrors.IsNotFound(err) {
		// Get ServiceInfos for consumed BTP services
		consumedServiceInfos := getConsumedServiceInfos(getConsumedServiceMap(workload.ConsumedBTPServices), ca.Spec.BTP.Services)

		// Create ownerRef to CAV
		ownerRef := *metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind))

		// Get VCAP secret name
		vcapSecretName, err = createVCAPSecret(deploymentName, cav.Namespace, ownerRef, consumedServiceInfos, c.kubeClient)

		if err == nil {
			workloadDeployment, err = c.kubeClient.AppsV1().Deployments(cav.Namespace).Create(context.TODO(), newDeployment(ca, cav, workload, ownerRef, vcapSecretName), metav1.CreateOptions{})
		}
	}

	return doChecks(err, workloadDeployment, cav, workload.Name)
}

// newDeployment creates a new generic Deployment for a CAV resource based on the type. It also sets the appropriate OwnerReferences.
func newDeployment(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, workload *v1alpha1.WorkloadDetails, ownerRef metav1.OwnerReference, vcapSecretName string) *appsv1.Deployment {
	params := &DeploymentParameters{
		CA:              ca,
		CAV:             cav,
		OwnerRef:        &ownerRef,
		WorkloadDetails: *workload,
		VCAPSecretName:  vcapSecretName,
	}

	return createDeployment(params)
}

func createDeployment(params *DeploymentParameters) *appsv1.Deployment {
	workloadName := params.CAV.Name + "-" + strings.ToLower(params.WorkloadDetails.Name)
	annotations := copyMaps(params.WorkloadDetails.Annotations, getAnnotations(params.CA, params.CAV, true))
	labels := copyMaps(params.WorkloadDetails.Labels, getLabels(params.CA, params.CAV, CategoryWorkload, string(params.WorkloadDetails.DeploymentDefinition.Type), workloadName, true))

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      workloadName,
			Namespace: params.CAV.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*params.OwnerRef,
			},
			Annotations: annotations,
			Labels:      labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Replicas: params.WorkloadDetails.DeploymentDefinition.Replicas, // will automatically default to 1 (if pointer is nil)
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets:          convertToLocalObjectReferences(params.CAV.Spec.RegistrySecrets),
					Containers:                getContainer(params),
					ServiceAccountName:        params.WorkloadDetails.DeploymentDefinition.ServiceAccountName,
					Volumes:                   params.WorkloadDetails.DeploymentDefinition.Volumes,
					SecurityContext:           params.WorkloadDetails.DeploymentDefinition.PodSecurityContext,
					NodeSelector:              params.WorkloadDetails.DeploymentDefinition.NodeSelector,
					NodeName:                  params.WorkloadDetails.DeploymentDefinition.NodeName,
					PriorityClassName:         params.WorkloadDetails.DeploymentDefinition.PriorityClassName,
					Affinity:                  params.WorkloadDetails.DeploymentDefinition.Affinity,
					TopologySpreadConstraints: params.WorkloadDetails.DeploymentDefinition.TopologySpreadConstraints,
					Tolerations:               params.WorkloadDetails.DeploymentDefinition.Tolerations,
				},
			},
		},
	}
}

func getContainer(params *DeploymentParameters) []corev1.Container {
	container := corev1.Container{
		Name:            params.WorkloadDetails.Name,
		Image:           params.WorkloadDetails.DeploymentDefinition.Image,
		ImagePullPolicy: params.WorkloadDetails.DeploymentDefinition.ImagePullPolicy,
		Command:         params.WorkloadDetails.DeploymentDefinition.Command,
		Env:             getEnv(params),
		EnvFrom:         getEnvFrom(params.VCAPSecretName),
		VolumeMounts:    params.WorkloadDetails.DeploymentDefinition.VolumeMounts,
		LivenessProbe:   params.WorkloadDetails.DeploymentDefinition.LivenessProbe,
		ReadinessProbe:  params.WorkloadDetails.DeploymentDefinition.ReadinessProbe,
		Resources:       params.WorkloadDetails.DeploymentDefinition.Resources,
		SecurityContext: params.WorkloadDetails.DeploymentDefinition.SecurityContext,
	}
	return []corev1.Container{container}
}

func getEnv(params *DeploymentParameters) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: EnvCAPOpAppVersion, Value: params.CAV.Spec.Version},
	}
	env = append(env, params.WorkloadDetails.DeploymentDefinition.Env...)

	if params.WorkloadDetails.DeploymentDefinition.Type == v1alpha1.DeploymentRouter {
		// Add destinations env for `Router`
		appendDestinationsEnv(params.CAV, &env)
	}

	return env
}

func appendDestinationsEnv(cav *v1alpha1.CAPApplicationVersion, env *[]corev1.EnvVar) {
	var (
		destEnvIndex int                          = -1
		destMap      map[string]RouterDestination = map[string]RouterDestination{}
	)

	destEnvIndex = slices.IndexFunc(*env, func(currentEnv corev1.EnvVar) bool { return currentEnv.Name == "destinations" })

	if destEnvIndex > -1 {
		if destinations, err := util.ParseJSON[[]RouterDestination]([]byte((*env)[destEnvIndex].Value)); err == nil {
			for _, d := range *destinations {
				destMap[d.Name] = d
			}
		} // else -> in case of parsing error continue with only the workload destinations
	}

	destinations := []RouterDestination{}
	portInfos := getRelevantServicePortInfo(cav)
	for _, portInfo := range portInfos {
		for _, destinationInfo := range portInfo.Destinations {
			dest := getDestination(destMap, destinationInfo, portInfo)
			destinations = append(destinations, dest)
			delete(destMap, destinationInfo.DestinationName)
		}
	}

	for _, d := range destMap {
		destinations = append(destinations, d)
	}
	serialized, _ := json.Marshal(destinations)
	if destEnvIndex > -1 {
		(*env)[destEnvIndex].Value = string(serialized)
	} else {
		*env = append(*env, corev1.EnvVar{Name: "destinations", Value: string(serialized)})
	}
}

func getDestination(destMap map[string]RouterDestination, destinationInfo destinationInfo, portInfo servicePortInfo) RouterDestination {
	dest, ok := destMap[destinationInfo.DestinationName]
	if !ok {
		dest = RouterDestination{
			Name:             destinationInfo.DestinationName,
			URL:              "http://" + portInfo.WorkloadName + ServiceSuffix + ":" + strconv.Itoa(int(destinationInfo.Port)),
			ForwardAuthToken: true,
		}
	} else {
		// Overwrite just the URL from existing destination configuration
		dest.URL = "http://" + portInfo.WorkloadName + ServiceSuffix + ":" + strconv.Itoa(int(destinationInfo.Port))
	}
	return dest
}

// endregion Deployments

func getEnvFrom(vcapServiceName string) []corev1.EnvFromSource {
	return []corev1.EnvFromSource{
		{
			SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: vcapServiceName,
				},
				Optional: &trueVal,
			},
		},
	}
}

func (c *Controller) prepareCAPApplicationVersion(ctx context.Context, cav *v1alpha1.CAPApplicationVersion) (update bool, err error) {
	// Do nothing when object is deleted
	if cav.DeletionTimestamp != nil {
		return false, nil
	}
	ca, err := c.getCachedCAPApplication(cav.Namespace, cav.Spec.CAPApplicationInstance)
	if err != nil {
		return false, err
	}
	if _, ok := getOwnerByKind(cav.OwnerReferences, v1alpha1.CAPApplicationKind); !ok {
		// create owner reference - CAPApplication
		cav.OwnerReferences = append(cav.OwnerReferences, *metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind)))
		update = true
	}

	if addCAPApplicationVersionLabels(cav, ca) {
		update = true
	}

	if cav.DeletionTimestamp == nil {
		// Finalizer to prevent direct deletion of CAPApplicationVersion
		if cav.Finalizers == nil {
			cav.Finalizers = []string{}
		}
		if addFinalizer(&cav.Finalizers, FinalizerCAPApplicationVersion) {
			update = true
		}
	}

	return update, nil
}

// Annotations
func getAnnotations(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, ownerInfo bool) map[string]string {
	annotations := map[string]string{
		AnnotationBTPApplicationIdentifier: strings.Join([]string{ca.Spec.GlobalAccountId, ca.Spec.BTPAppName}, "."),
	}

	if ownerInfo {
		annotations[AnnotationOwnerIdentifier] = cav.Namespace + "." + cav.Name

	}

	return annotations
}

// Labels
func getLabels(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, category string, workloadType string, workloadName string, additionalDetails bool) map[string]string {
	labels := map[string]string{
		App:                               ca.Spec.BTPAppName,
		LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName),
		LabelCAVVersion:                   cav.Spec.Version,
		LabelResourceCategory:             category,
	}

	addIfNotEmpty := func(k, v string) {
		if v != "" {
			labels[k] = v
		}
	}
	addIfNotEmpty(LabelWorkloadType, workloadType)
	addIfNotEmpty(LabelWorkloadName, workloadName)

	if additionalDetails {
		labels[LabelOwnerIdentifierHash] = sha1Sum(cav.Namespace, cav.Name)
		labels[LabelOwnerGeneration] = strconv.FormatInt(cav.Generation, 10)
	}

	return labels
}

func addCAPApplicationVersionLabels(cav *v1alpha1.CAPApplicationVersion, ca *v1alpha1.CAPApplication) (updated bool) {
	appMetadata := appMetadataIdentifiers{
		globalAccountId: ca.Spec.GlobalAccountId,
		appName:         ca.Spec.BTPAppName,
		ownerInfo: &ownerInfo{
			ownerNamespace:  ca.Namespace,
			ownerName:       ca.Name,
			ownerGeneration: ca.Generation,
		},
	}
	if updateLabelAnnotationMetadata(&cav.ObjectMeta, &appMetadata) {
		updated = true
	}
	return updated
}

// Check if an error occurred or if owner references are correct
func doChecks(err error, obj metav1.Object, cav *v1alpha1.CAPApplicationVersion, res string) error {
	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// Check if the Deployment is not controlled by this CustomDeployment resource
	_, ok := getOwnerByKind(obj.GetOwnerReferences(), v1alpha1.CAPApplicationVersionKind)
	if !ok {
		return fmt.Errorf("%s could not be identified for the resource %s %s: %s.%s", v1alpha1.CAPApplicationVersionKind, res, obj.GetName(), cav.Namespace, cav.Name)
	}

	return nil
}

func getContentJobInOrder(cav *v1alpha1.CAPApplicationVersion) []string {
	if cav.Spec.ContentJobs == nil {
		contentJob := getRelevantJob(v1alpha1.JobContent, cav)
		if contentJob == nil {
			return nil
		}
		return []string{contentJob.Name}
	}
	return cav.Spec.ContentJobs
}

func checkAndUpdateJobStatusFinishedJobs(contentDeployJob *batchv1.Job, cav *v1alpha1.CAPApplicationVersion) error {
	if contentDeployJob == nil {
		return nil
	}
	for _, condition := range contentDeployJob.Status.Conditions {
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			cav.SetStatusFinishedJobs(contentDeployJob.Name)
		} else if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
			cav.SetStatusFinishedJobs(contentDeployJob.Name)
			return fmt.Errorf("%s", condition.Message)
		}
	}
	return nil
}

func (c *Controller) checkContentWorkloadStatus(ctx context.Context, cav *v1alpha1.CAPApplicationVersion) (bool, error) {
	// Once the cav goes into Error state, we should not check the jobs again in the next reconciliation loop
	// because it could happen that the job can get deleted meanwhile and we won't be able
	// to determine the state of the job correctly.
	if len(cav.Status.Conditions) > 0 && cav.Status.Conditions[0].Reason == "ErrorInWorkloadStatus" {
		return false, fmt.Errorf("%s", cav.Status.Conditions[0].Message)
	}

	for _, contentJobName := range getContentJobInOrder(cav) {

		job := getContentJobName(contentJobName, cav)

		// Get the contentDeploy job with the name expected for this CAV instance
		// The job could get deleted after sometime. So we should also check the finished job list on the CAV status.
		contentDeployJob, err := c.kubeInformerFactory.Batch().V1().Jobs().Lister().Jobs(cav.Namespace).Get(job)
		if err != nil && !cav.CheckFinishedJobs(job) {
			return true, nil
		}

		numOfFinishedJobsBeforeUpd := len(cav.Status.FinishedJobs)
		if err := checkAndUpdateJobStatusFinishedJobs(contentDeployJob, cav); err != nil {
			return false, err
		}

		if numOfFinishedJobsBeforeUpd != len(cav.Status.FinishedJobs) {
			if err := c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateProcessing, metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False", Reason: "ReadyForProcessing"}); err != nil {
				return false, err
			}
		}

		// If the job is still running, set processing to true
		if !cav.CheckFinishedJobs(job) {
			return true, nil
		}
	}

	// All Jobs are executed
	return false, nil
}

func (c *Controller) getRelevantTenantsForCAV(cav *v1alpha1.CAPApplicationVersion) []*v1alpha1.CAPTenant {
	var tenants []*v1alpha1.CAPTenant
	// Get CAPApplication instance
	ca, _ := c.getCachedCAPApplication(cav.Namespace, cav.Spec.CAPApplicationInstance)
	if ca != nil {
		// Get all tenants in the namespace for the CAPApplication
		allTenants, _ := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().CAPTenants(cav.Namespace).List(labels.SelectorFromSet(map[string]string{LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName)}))
		// Filter out relevant tenants for the CAPApplicationVersion
		for _, tenant := range allTenants {
			// If a tenant is already on a given version -or- is being provisioned/upgraded to a version, it is relevant for this CAPApplicationVersion
			if tenant.Status.CurrentCAPApplicationVersionInstance == cav.Name || tenant.Spec.Version == cav.Spec.Version {
				tenants = append(tenants, tenant)
			}
		}
	}
	return tenants
}

func (c *Controller) deleteCAPApplicationVersion(ctx context.Context, cav *v1alpha1.CAPApplicationVersion) (*ReconcileResult, error) {
	// Update State if it is not set yet
	if cav.Status.State != v1alpha1.CAPApplicationVersionStateDeleting {
		var deleteCondition metav1.Condition
		if len(cav.Status.Conditions) > 0 {
			deleteCondition = *cav.Status.Conditions[0].DeepCopy() // Reuse the existing condition during deletion
		} else {
			deleteCondition = metav1.Condition{Type: string(v1alpha1.ConditionTypeReady), Status: "False"}
		}
		// Set the reason for Deletion
		deleteCondition.Reason = "DeleteTriggered"
		err := c.updateCAPApplicationVersionStatus(ctx, cav, v1alpha1.CAPApplicationVersionStateDeleting, deleteCondition)
		if err != nil {
			return nil, err
		}
	}

	tenants := c.getRelevantTenantsForCAV(cav)

	// Check if tenants exists
	if len(tenants) > 0 {
		// Requeue after 10s to check if all tenants are gone
		return NewReconcileResultWithResource(ResourceCAPApplicationVersion, cav.Name, cav.Namespace, 10*time.Second), nil
	} else if removeFinalizer(&cav.Finalizers, FinalizerCAPApplicationVersion) { // All tenants are gone --> remove finalizer and process deletion
		return nil, c.updateCAPApplicationVersion(ctx, cav)
	}

	// No finalizer exists
	return nil, nil
}
