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

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/mod/semver"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	LabelOwnerIdentifierHash            = "sme.sap.com/owner-identifier-hash"
	LabelOwnerGeneration                = "sme.sap.com/owner-generation"
	LabelWorkloadName                   = "sme.sap.com/workload-name"
	LabelWorkloadType                   = "sme.sap.com/workload-type"
	LabelResourceCategory               = "sme.sap.com/category"
	LabelBTPApplicationIdentifierHash   = "sme.sap.com/btp-app-identifier-hash"
	LabelTenantType                     = "sme.sap.com/tenant-type"
	LabelTenantId                       = "sme.sap.com/btp-tenant-id"
	LabelTenantOperationType            = "sme.sap.com/tenant-operation-type"
	LabelTenantOperationStep            = "sme.sap.com/tenant-operation-step"
	LabelCAVVersion                     = "sme.sap.com/cav-version"
	LabelRelevantDNSTarget              = "sme.sap.com/relevant-dns-target-hash"
	LabelDisableKarydia                 = "x4.sap.com/disable-karydia"
	LabelExposedWorkload                = "sme.sap.com/exposed-workload"
	LabelSubdomainHash                  = "sme.sap.com/subdomain-hash"
	AnnotationOwnerIdentifier           = "sme.sap.com/owner-identifier"
	AnnotationBTPApplicationIdentifier  = "sme.sap.com/btp-app-identifier"
	AnnotationResourceHash              = "sme.sap.com/resource-hash"
	AnnotationControllerClass           = "sme.sap.com/controller-class"
	AnnotationIstioSidecarInject        = "sidecar.istio.io/inject"
	AnnotationGardenerDNSTarget         = "dns.gardener.cloud/dnsnames"
	AnnotationKubernetesDNSTarget       = "external-dns.alpha.kubernetes.io/hostname"
	AnnotationSubscriptionContextSecret = "sme.sap.com/subscription-context-secret"
	AnnotationProviderSubAccountId      = "sme.sap.com/provider-sub-account-id"
	AnnotationEnableCleanupMonitoring   = "sme.sap.com/enable-cleanup-monitoring"
	FinalizerCAPApplication             = "sme.sap.com/capapplication"
	FinalizerCAPApplicationVersion      = "sme.sap.com/capapplicationversion"
	FinalizerCAPTenant                  = "sme.sap.com/captenant"
	FinalizerCAPTenantOperation         = "sme.sap.com/captenantoperation"
	FinalizerDomain                     = "sme.sap.com/domain"
	GardenerDNSClassIdentifier          = "dns.gardener.cloud/class"
)

const (
	CertificateSuffix     = "certificate"
	GardenerDNSClassValue = "garden"
	GatewaySuffix         = "gw"
	IstioSystemNamespace  = "istio-system"
	SecretSuffix          = "secret"
)

var (
	backoffLimitValue            int32 = 2
	tTLSecondsAfterFinishedValue int32 = 300
)

const (
	ProviderTenantType = "provider"
	ConsumerTenantType = "consumer"
)

// Use a different name for sticky cookie than the one from approuter (JSESSIONID) used for session handling
const RouterHttpCookieName = "CAPOP_ROUTER_STICKY"

const (
	EnvCAPOpAppVersion          = "CAPOP_APP_VERSION"
	EnvCAPOpTenantId            = "CAPOP_TENANT_ID"
	EnvCAPOpTenantSubDomain     = "CAPOP_TENANT_SUBDOMAIN"
	EnvCAPOpTenantOperation     = "CAPOP_TENANT_OPERATION"
	EnvCAPOpTenantMtxsOperation = "CAPOP_TENANT_MTXS_OPERATION"
	EnvCAPOpTenantType          = "CAPOP_TENANT_TYPE"
	EnvCAPOpAppName             = "CAPOP_APP_NAME"
	EnvCAPOpGlobalAccountId     = "CAPOP_GLOBAL_ACCOUNT_ID"
	EnvCAPOpProviderTenantId    = "CAPOP_PROVIDER_TENANT_ID"
	EnvCAPOpProviderSubDomain   = "CAPOP_PROVIDER_SUBDOMAIN"
	EnvCAPOpSubscriptionPayload = "CAPOP_SUBSCRIPTION_PAYLOAD"
	EnvVCAPServices             = "VCAP_SERVICES"
)

type JobState string

const (
	JobStateComplete   JobState = "Complete"
	JobStateFailed     JobState = "Failed"
	JobStateProcessing JobState = "Processing"
)

type ingressGatewayInfo struct {
	Namespace string
	Name      string
	DNSTarget string
}

type servicePortInfo struct {
	WorkloadName   string
	DeploymentType string
	Ports          []corev1.ServicePort
	ClusterPorts   []int32
	Destinations   []destinationInfo
}

type destinationInfo struct {
	DestinationName string
	Port            int32
}

const (
	ServiceSuffix       = "-svc"
	SubscriptionContext = "subscriptionContext"
)

var restrictedEnvNames = map[string]struct{}{
	EnvCAPOpAppVersion: {},
	EnvVCAPServices:    {},
}

// See https://www.npmjs.com/package/@sap/approuter#destinations
type RouterDestination struct {
	Name                 string `json:"name"`
	URL                  string `json:"url"`
	ProxyHost            string `json:"proxyHost,omitempty"`
	ProxyPort            string `json:"proxyPort,omitempty"`
	ForwardAuthToken     bool   `json:"forwardAuthToken,omitempty"`
	StrictSSL            bool   `json:"strictSSL,omitempty"`
	Timeout              *int64 `json:"timeout,omitempty"`
	SetXForwardedHeaders bool   `json:"setXForwardedHeaders,omitempty"`
	ProxyType            string `json:"proxyType,omitempty"`
}

type Steps string

const (
	Processing     Steps = "Processing"
	Provisioning   Steps = "Provisioning"
	Upgrading      Steps = "Upgrading"
	Deprovisioning Steps = "Deprovisioning"
	Deleting       Steps = "Deleting"
	Ready          Steps = "Ready"
	Error          Steps = "Error"
)

func (c *Controller) Event(main runtime.Object, related runtime.Object, eventType, reason, action, message string) {
	defer func() {
		// do not let the routine dump due to event recording errors
		if r := recover(); r != nil {
			klog.ErrorS(nil, "error when recording event", "recovered error", r)
		}
	}()
	c.eventRecorder.Eventf(main, related, eventType, reason, action, message)
}

func (c *Controller) getCachedCAPApplication(namespace string, name string) (*v1alpha1.CAPApplication, error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister()
	return lister.CAPApplications(namespace).Get(name)
}

func (c *Controller) getCachedCAPTenant(namespace string, value string, valueIsTenantId bool) (*v1alpha1.CAPTenant, error) {
	lister := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister()
	if !valueIsTenantId {
		// fetch with name
		return lister.CAPTenants(namespace).Get(value)
	}

	// fetch with label selector
	set := map[string]string{LabelTenantId: value}
	selector, err := labels.ValidatedSelectorFromSet(set)
	if err != nil {
		return nil, err
	}

	cats, err := lister.CAPTenants(namespace).List(selector)
	if err != nil {
		return nil, err
	}
	if len(cats) == 0 {
		return nil, fmt.Errorf("could not find CAPTenant with tenant id %s", value)
	}
	return cats[0], nil // expect only one matching tenant
}

/*
fetch the latest CAPApplicationVersion in Ready state, for a specified CAPApplication
*/
func (c *Controller) getLatestReadyCAPApplicationVersion(ctx context.Context, ca *v1alpha1.CAPApplication, avoidNotFound bool) (*v1alpha1.CAPApplicationVersion, error) {
	cavs, err := c.getCachedCAPApplicationVersions(ctx, ca)
	if err != nil {
		return nil, err
	}

	var latestCav *v1alpha1.CAPApplicationVersion
	for _, cav := range cavs {
		// determine the latest semantic version
		if isCROConditionReady(cav.Status.GenericStatus) &&
			(latestCav == nil || semver.Compare("v"+cav.Spec.Version, "v"+latestCav.Spec.Version) == 1) {
			latestCav = cav
		}
	}

	if latestCav == nil && !avoidNotFound {
		err = fmt.Errorf("could not find a %s with status %s for %s %s.%s", v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPApplicationVersionStateReady, v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
	}

	return latestCav, err
}

/*
fetch the latest CAPApplicationVersion, for a specified CAPApplication
*/
func (c *Controller) getLatestCAPApplicationVersion(ctx context.Context, ca *v1alpha1.CAPApplication) (*v1alpha1.CAPApplicationVersion, error) {
	cavs, err := c.getCachedCAPApplicationVersions(ctx, ca)
	if err != nil {
		return nil, err
	}

	var latestCav *v1alpha1.CAPApplicationVersion
	for _, cav := range cavs {
		// determine the latest semantic version
		if latestCav == nil || semver.Compare("v"+cav.Spec.Version, "v"+latestCav.Spec.Version) == 1 {
			latestCav = cav
		}
	}

	if latestCav == nil {
		err = fmt.Errorf("could not find a %s for %s %s.%s", v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name)
	}

	return latestCav, err
}

/*
*

	fetch the relevant CAPApplicationVersion in Ready state, for a specified CAPApplication and version string
*/
func (c *Controller) getRelevantCAPApplicationVersion(ctx context.Context, ca *v1alpha1.CAPApplication, version string) (*v1alpha1.CAPApplicationVersion, error) {
	cavs, err := c.getCachedCAPApplicationVersions(ctx, ca)
	if err != nil {
		return nil, err
	}

	var latestCav *v1alpha1.CAPApplicationVersion
	for _, cav := range cavs {
		// determine the matching semantic version and return
		if isCROConditionReady(cav.Status.GenericStatus) && cav.Spec.Version == version {
			latestCav = cav
			break
		}
	}

	if latestCav == nil {
		err = fmt.Errorf("could not find a %s with status %s for %s %s.%s and version %s", v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPApplicationVersionStateReady, v1alpha1.CAPApplicationKind, ca.Namespace, ca.Name, version)
	}

	return latestCav, err
}

func (c *Controller) getCachedCAPApplicationVersions(ctx context.Context, ca *v1alpha1.CAPApplication) ([]*v1alpha1.CAPApplicationVersion, error) {
	selector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelOwnerIdentifierHash: sha1Sum(ca.Namespace, ca.Name),
	})

	if err != nil {
		return nil, err
	}

	return c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().List(selector)
}

func (c *Controller) checkSecretsExist(serviceInfos []v1alpha1.ServiceInfo, namespace string) error {
	var err error
	secretLister := c.kubeInformerFactory.Core().V1().Secrets().Lister()

	for _, service := range serviceInfos {
		secretName := service.Secret
		if _, err = secretLister.Secrets(namespace).Get(secretName); err != nil {
			break
		}
	}
	return err
}

func (c *Controller) checkAndPreserveSecrets(serviceInfos []v1alpha1.ServiceInfo, namespace string) error {
	var err error
	var secret *corev1.Secret
	secretLister := c.kubeInformerFactory.Core().V1().Secrets().Lister()

	for _, service := range serviceInfos {
		secretName := service.Secret
		if secret, err = secretLister.Secrets(namespace).Get(secretName); err != nil {
			break
		}
		// Add finalizer to preserve Secret from being deleted accidentally
		if addFinalizer(&secret.Finalizers, FinalizerCAPApplication) {
			if _, err = c.kubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
				break
			}
		}
	}
	return err
}

func (c *Controller) cleanupPreservedSecrets(serviceInfos []v1alpha1.ServiceInfo, namespace string) error {
	var err error
	var secret *corev1.Secret
	secretLister := c.kubeInformerFactory.Core().V1().Secrets().Lister()

	for _, service := range serviceInfos {
		secretName := service.Secret
		// Check if a secret exists
		if secret, err = secretLister.Secrets(namespace).Get(secretName); err != nil && !k8sErrors.IsNotFound(err) {
			break
		}
		// Remove finalizer from preserved Secret (if one exists) to allow it to be cleaned up if needed
		if secret != nil && removeFinalizer(&secret.Finalizers, FinalizerCAPApplication) {
			if _, err = c.kubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
				break
			}
		}
	}
	return err
}

func (c *Controller) checkServicesOnly(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) error {
	servicesOnly := !slices.ContainsFunc(cav.Spec.Workloads, func(wd v1alpha1.WorkloadDetails) bool {
		if wd.JobDefinition != nil {
			return wd.JobDefinition.Type != v1alpha1.JobContent
		}
		return wd.DeploymentDefinition != nil && wd.DeploymentDefinition.Type != v1alpha1.DeploymentService
	})

	// Check if the CAP Application is already marked with ServicesOnly from a previous version only once the Status is set!
	if ca.Status.ServicesOnly != nil {
		if ca.IsServicesOnly() != servicesOnly {
			serviceErrorPrefix := "without"
			if servicesOnly {
				serviceErrorPrefix = "with"
			}
			return fmt.Errorf("Creating a new version %s only service workloads is not allowed. The CAP Application %s.%s is already marked with ServicesOnly %v from a previous version", serviceErrorPrefix, ca.Namespace, ca.Name, !servicesOnly)
		}
	}

	// Set ServicesOnly status according to the first ready CAV workload configuration
	ca.SetStatusServicesOnly(&servicesOnly)

	return nil
}

// This method is called to handle NotFound error at the beginning of reconciliation to skip requeue on errors due to deletion of resource
func handleOperatorResourceErrors(err error) error {
	// Handle NotFound errors (object was most likely deleted)
	if k8sErrors.IsNotFound(err) {
		return nil // No error, to skips requeue of the resource
	}
	return err
}

func getConsumedServiceMap(consumedServices []string) map[string]string {
	// Create a Map of consumedServices
	consumedServicesMap := make(map[string]string)
	for _, consumedService := range consumedServices {
		consumedServicesMap[consumedService] = consumedService
	}
	return consumedServicesMap
}

func getConsumedServiceInfos(consumedServicesMap map[string]string, serviceInfos []v1alpha1.ServiceInfo) []v1alpha1.ServiceInfo {
	consumedServiceInfo := []v1alpha1.ServiceInfo{}

	for _, serviceInfo := range serviceInfos {
		if serviceInfo.Name == consumedServicesMap[serviceInfo.Name] {
			consumedServiceInfo = append(consumedServiceInfo, serviceInfo)
		}
	}
	return consumedServiceInfo
}

func generateVCAPEnv(ns string, serviceInfos []v1alpha1.ServiceInfo, kubeClient kubernetes.Interface) ([]byte, error) {
	envVCAPServices := map[string][]map[string]any{}
	for _, serviceInfo := range serviceInfos {
		entry, err := util.CreateVCAPEntryFromSecret(&serviceInfo, ns, kubeClient)
		if err != nil {
			return nil, err
		}

		// Generate vcap_service info for the class
		if envVCAPServices[serviceInfo.Class] == nil {
			envVCAPServices[serviceInfo.Class] = []map[string]any{}
		}
		// Simulate attributes that describe a bound service (@TODO: consider adding tags, binding_name, plan etc..)
		envVCAPServices[serviceInfo.Class] = append(envVCAPServices[serviceInfo.Class], entry)
	}

	// Return stringified vcap env
	return json.Marshal(envVCAPServices)
}

func createVCAPSecret(namePrefix string, ns string, ownerRef metav1.OwnerReference, serviceInfos []v1alpha1.ServiceInfo, kubeClient kubernetes.Interface) (string, error) {
	// Generate VCAP_SERVICES env. variable
	vcapEnv, err := generateVCAPEnv(ns, serviceInfos, kubeClient)
	if err != nil {
		return "", err
	}

	// Create a secret for VCAP_SERVICES for the given workload
	secret, err := kubeClient.CoreV1().Secrets(ns).Create(context.TODO(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    namePrefix + "-",
				OwnerReferences: []metav1.OwnerReference{ownerRef},
			},
			StringData: map[string]string{
				EnvVCAPServices: string(vcapEnv),
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", err
	}
	// Successfully created deployment secret --> return name
	// @TODO: Reconcile CAV once we expect secrets/credentials to be updated
	return secret.Name, nil
}

func validateEnv(envConfig []corev1.EnvVar, restrictedNames map[string]struct{}) string {
	for _, envConfigEntry := range envConfig {
		if _, ok := restrictedNames[envConfigEntry.Name]; ok {
			return envConfigEntry.Name
		}
	}
	// No restricted entries found
	return ""
}

func errorEnv(workloadType string, entry string) error {
	return fmt.Errorf("invalid env configuration for workload: %s, remove entry: %s from configuration", workloadType, entry)
}

func getRelevantJob(workloadType v1alpha1.JobType, cav *v1alpha1.CAPApplicationVersion) *v1alpha1.WorkloadDetails {
	for _, workload := range cav.Spec.Workloads {
		if workload.JobDefinition != nil && workload.JobDefinition.Type == workloadType {
			return &workload
		}
	}
	return nil
}

func getRelevantDeployment(workloadType v1alpha1.DeploymentType, cav *v1alpha1.CAPApplicationVersion) *v1alpha1.WorkloadDetails {
	workloads := getDeployments(workloadType, cav)
	if len(workloads) == 0 {
		return nil
	}
	return &workloads[0]
}

func getDeployments(workloadType v1alpha1.DeploymentType, cav *v1alpha1.CAPApplicationVersion) []v1alpha1.WorkloadDetails {
	deployments := []v1alpha1.WorkloadDetails{}
	for _, workload := range cav.Spec.Workloads {
		if workload.DeploymentDefinition != nil && workload.DeploymentDefinition.Type == workloadType {
			deployments = append(deployments, workload)
		}
	}
	return deployments
}

func getWorkloadByName(name string, cav *v1alpha1.CAPApplicationVersion) *v1alpha1.WorkloadDetails {
	for _, workload := range cav.Spec.Workloads {
		if workload.Name == name {
			return &workload
		}
	}
	return nil
}

func getJobState(job *batchv1.Job) JobState {
	// check for completion
	for _, condition := range job.Status.Conditions {
		if condition.Status == corev1.ConditionTrue {
			var state JobState
			switch condition.Type {
			case batchv1.JobComplete:
				state = JobStateComplete
			case batchv1.JobFailed:
				state = JobStateFailed
			default:
				continue
			}
			return state
		}
	}

	// probably the job is still in process
	return JobStateProcessing
}

func isDeletionImminent(m *metav1.ObjectMeta) bool {
	if m.DeletionTimestamp == nil {
		return false
	}
	return len(m.Finalizers) == 0
}

func getRelevantServicePortInfo(cav *v1alpha1.CAPApplicationVersion) []servicePortInfo {
	overallPortInfos := []servicePortInfo{}
	for _, workload := range cav.Spec.Workloads {
		var workloadPortInfo *servicePortInfo
		if workload.DeploymentDefinition != nil {
			workloadPortInfo = getWorkloadPortInfo(workload, cav.Name)
		}

		if workloadPortInfo != nil {
			overallPortInfos = append(overallPortInfos, *workloadPortInfo)
		}
	}
	return overallPortInfos
}

func getWorkloadPortInfo(workload v1alpha1.WorkloadDetails, cavName string) *servicePortInfo {
	var servicePorts []corev1.ServicePort
	var destinationDetails []destinationInfo
	var clusterPorts []int32
	if len(workload.DeploymentDefinition.Ports) > 0 {
		servicePorts = []corev1.ServicePort{}
		destinationDetails = []destinationInfo{}
		clusterPorts = []int32{}
		for _, port := range workload.DeploymentDefinition.Ports {
			servicePorts = append(servicePorts, corev1.ServicePort{Name: port.Name, Port: port.Port, AppProtocol: port.AppProtocol})
			if port.RouterDestinationName != "" {
				destinationDetails = append(destinationDetails, destinationInfo{
					DestinationName: port.RouterDestinationName,
					Port:            port.Port,
				})
			}
			if port.NetworkPolicy == v1alpha1.PortNetworkPolicyTypeCluster {
				clusterPorts = append(clusterPorts, port.Port)
			}
		}
	}
	workloadPortInfo := updateWorkloadPortInfo(cavName, workload.Name, workload.DeploymentDefinition.Type, servicePorts, destinationDetails, clusterPorts)
	return workloadPortInfo
}

func updateWorkloadPortInfo(cavName string, workloadName string, deploymentType v1alpha1.DeploymentType, servicePorts []corev1.ServicePort, destinationDetails []destinationInfo, clusterPorts []int32) *servicePortInfo {
	var workloadPortInfo *servicePortInfo
	if len(servicePorts) == 0 {
		// Use fallback defaults
		if deploymentType == v1alpha1.DeploymentRouter {
			servicePorts = []corev1.ServicePort{
				{Name: "router-svc-port", Port: defaultRouterPort},
			}
		} else if deploymentType == v1alpha1.DeploymentCAP {
			servicePorts = []corev1.ServicePort{
				{Name: "server-svc-port", Port: defaultServerPort},
			}
			// When there are no ports there can be no destinations, just create a default one for CAP backend
			destinationDetails = append([]destinationInfo{}, destinationInfo{
				DestinationName: "srv-api",
				Port:            defaultServerPort,
			})
		}
	}

	if len(servicePorts) > 0 {
		workloadPortInfo = &servicePortInfo{
			WorkloadName:   getWorkloadName(cavName, workloadName),
			DeploymentType: string(deploymentType),
			Ports:          servicePorts,
			Destinations:   destinationDetails,
			ClusterPorts:   clusterPorts,
		}
	}

	return workloadPortInfo
}

func getServicePortInfoByWorkloadName(items []servicePortInfo, cavName string, workloadName string) *servicePortInfo {
	for i := range items {
		current := items[i]
		if current.WorkloadName == getWorkloadName(cavName, workloadName) {
			return &current
		}
	}
	return nil
}

func (c *Controller) getRouterServicePortInfo(cavName string, namespace string) (*servicePortInfo, error) {
	cav, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(namespace).Get(cavName)
	if err != nil {
		return nil, err
	}

	routerWorkload := getRelevantDeployment(v1alpha1.DeploymentRouter, cav)

	return getWorkloadPortInfo(*routerWorkload, cavName), nil
}

func copyMaps(originalMap map[string]string, additionalMap map[string]string) map[string]string {
	newMap := map[string]string{}
	for key, value := range originalMap {
		newMap[key] = value
	}
	for key, value := range additionalMap {
		newMap[key] = value
	}
	return newMap
}

func updateInitContainers(initContainers []corev1.Container, additionalEnv []corev1.EnvVar, vcapSecretName string) *[]corev1.Container {
	var updatedInitContainers []corev1.Container
	if len(initContainers) > 0 {
		updatedInitContainers = []corev1.Container{}
		for _, container := range initContainers {
			updatedContainer := container.DeepCopy()
			updatedContainer.Env = append(updatedContainer.Env, additionalEnv...)
			updatedContainer.EnvFrom = getEnvFrom(vcapSecretName)
			updatedInitContainers = append(updatedInitContainers, *updatedContainer)
		}
	}
	return &updatedInitContainers
}

func getWorkloadName(cavName, workloadName string) string {
	return fmt.Sprintf("%s-%s", cavName, strings.ToLower(workloadName))
}

func getRestartPolicy(restartPolicy corev1.RestartPolicy, isJob bool) corev1.RestartPolicy {
	if isJob && restartPolicy == "" {
		return corev1.RestartPolicyNever
	}
	return restartPolicy
}
