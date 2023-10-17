/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	Group                         = "sme.sap.com"
	Version                       = "v1alpha1"
	CAPApplicationKind            = "CAPApplication"
	CAPApplicationResource        = "capapplications"
	CAPApplicationVersionKind     = "CAPApplicationVersion"
	CAPApplicationVersionResource = "capapplicationversions"
	CAPTenantKind                 = "CAPTenant"
	CAPTenantResource             = "captenants"
	CAPTenantOperationKind        = "CAPTenantOperation"
	CAPTenantOperationResource    = "captenantoperations"
)

// +kubebuilder:resource:shortName=ca
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPApplication is the schema for capapplications API
type CAPApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPApplication spec
	Spec CAPApplicationSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPApplication status
	Status CAPApplicationStatus `json:"status"`
}

type CAPApplicationStatus struct {
	GenericStatus `json:",inline"`
	// +kubebuilder:validation:Enum="";Consistent;Processing;Error;Deleting
	// State of CAPApplication
	State CAPApplicationState `json:"state"`
	// Hash representing last known application domains
	DomainSpecHash string `json:"domainSpecHash,omitempty"`
	// The last time a full reconciliation was completed
	LastFullReconciliationTime metav1.Time `json:"lastFullReconciliationTime,omitempty"`
}

type CAPApplicationState string

const (
	// CAPApplication is being reconciled
	CAPApplicationStateProcessing CAPApplicationState = "Processing"
	// An error occurred during reconciliation
	CAPApplicationStateError CAPApplicationState = "Error"
	// Deletion has been triggered
	CAPApplicationStateDeleting CAPApplicationState = "Deleting"
	// CAPApplication has been reconciled and is now consistent
	CAPApplicationStateConsistent CAPApplicationState = "Consistent"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPApplicationList contains a list of CAPApplication
type CAPApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPApplication `json:"items"`
}

// CAPApplicationSpec defines the desired state of CAPApplication
type CAPApplicationSpec struct {
	// Domains used by the application
	Domains ApplicationDomains `json:"domains"`
	// SAP BTP Global Account Identifier where services are entitles for the current application
	GlobalAccountId string `json:"globalAccountId"`
	// Short name for the application (similar to BTP XSAPPNAME)
	BTPAppName string `json:"btpAppName"`
	// Provider subaccount where application services are created
	Provider BTPTenantIdentification `json:"provider"`
	// SAP BTP Services consumed by the application
	BTP BTP `json:"btp"`
}

// Application domains
type ApplicationDomains struct {
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
	// +kubebuilder:validation:MaxLength=62
	// Primary application domain will be used to generate a wildcard TLS certificate. In SAP Gardener managed clusters this is (usually) a subdomain of the cluster domain
	Primary string `json:"primary"`
	// Customer specific domains to serve application endpoints (optional)
	Secondary []string `json:"secondary,omitempty"`
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]*$
	// Public ingress URL for the cluster Load Balancer
	DnsTarget string `json:"dnsTarget,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// Labels used to identify the istio ingress-gateway component and its corresponding namespace. Usually {"app":"istio-ingressgateway","istio":"ingressgateway"}
	IstioIngressGatewayLabels []NameValue `json:"istioIngressGatewayLabels"`
}

//Workaround for pattern for string items +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
//type PatternString string

// Generic Name/Value configuration
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Identifies an SAP BTP subaccount (tenant)
type BTPTenantIdentification struct {
	// BTP subaccount subdomain
	SubDomain string `json:"subDomain"`
	// BTP subaccount Tenant ID
	TenantId string `json:"tenantId"`
}

type BTP struct {
	// Details of BTP Services
	Services []ServiceInfo `json:"services"`
}

// Service information
type ServiceInfo struct {
	// Name of service instance
	Name string `json:"name"`
	// Secret containing service access credentials
	Secret string `json:"secret"`
	// Type of service
	Class string `json:"class"`
	// TODO: enhance this with params and other options --> Needed if/when we want to create the services via BTP/CF Operator
}

// Custom resource status
type GenericStatus struct {
	// Observed generation of the resource where this status was identified
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// State expressed as conditions
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type CAPApplicationStatusConditionType string

const (
	ConditionTypeAllTenantsReady    CAPApplicationStatusConditionType = "AllTenantsReady"
	ConditionTypeLatestVersionReady CAPApplicationStatusConditionType = "LatestVersionReady"
)

type StatusConditionType string

const (
	ConditionTypeReady StatusConditionType = "Ready"
)

// +kubebuilder:resource:shortName=cav
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPApplicationVersion defines the schema for capapplicationversions API
type CAPApplicationVersion struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPApplicationVersion spec
	Spec CAPApplicationVersionSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPApplicationVersion status
	Status CAPApplicationVersionStatus `json:"status"`
}

type CAPApplicationVersionStatus struct {
	GenericStatus `json:",inline"`
	// +kubebuilder:validation:Enum="";Ready;Error;Processing;Deleting
	// State of CAPApplicationVersion
	State CAPApplicationVersionState `json:"state"`
	// List of finished Content Jobs
	FinishedJobs []string `json:"finishedJobs,omitempty"`
}

type CAPApplicationVersionState string

const (
	// CAPApplicationVersion is being processed
	CAPApplicationVersionStateProcessing CAPApplicationVersionState = "Processing"
	// An error occurred during reconciliation
	CAPApplicationVersionStateError CAPApplicationVersionState = "Error"
	// Deletion has been triggered
	CAPApplicationVersionStateDeleting CAPApplicationVersionState = "Deleting"
	// CAPApplicationVersion is now ready for use (dependent resources have been created)
	CAPApplicationVersionStateReady CAPApplicationVersionState = "Ready"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPApplicationVersionList contains a list of CAPApplicationVersion
type CAPApplicationVersionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPApplicationVersion `json:"items"`
}

// CAPApplicationVersionSpec specifies the desired state of CAPApplicationVersion
type CAPApplicationVersionSpec struct {
	// Denotes to which CAPApplication the current version belongs
	CAPApplicationInstance string `json:"capApplicationInstance"`
	// Semantic version
	Version string `json:"version"`
	// Registry secrets used to pull images of the application components
	RegistrySecrets []string `json:"registrySecrets,omitempty"`
	// Information about the Workloads
	Workloads []WorkloadDetails `json:"workloads"`
	// Tenant Operations may be used to specify how jobs are sequenced for the different tenant operations
	TenantOperations *TenantOperations `json:"tenantOperations,omitempty"`
	// Content Jobs may be used to specify the sequence of content jobs when several jobs exist
	ContentJobs []string `json:"contentJobs,omitempty"`
}

// WorkloadDetails specifies the details of the Workload
type WorkloadDetails struct {
	// Name of the workload
	Name string `json:"name"`
	// List of BTP services consumed by the current application component workload. These services must be defined in the corresponding CAPApplication.
	ConsumedBTPServices []string `json:"consumedBTPServices"`
	// Custom labels for the current workload
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations for the current workload, in case of `Deployments` this also get copied over to any `Service` that may be created
	Annotations map[string]string `json:"annotations,omitempty"`
	// Definition of a deployment
	DeploymentDefinition *DeploymentDetails `json:"deploymentDefinition,omitempty"`
	// Definition of a job
	JobDefinition *JobDetails `json:"jobDefinition,omitempty"`
}

// DeploymentDetails specifies the details of the Deployment
type DeploymentDetails struct {
	ContainerDetails `json:",inline"`
	// Type of the Deployment
	Type DeploymentType `json:"type"`
	// Number of replicas
	Replicas *int32 `json:"replicas,omitempty"`
	// Port configuration
	Ports []Ports `json:"ports,omitempty"`
	// Liveness probe
	LivenessProbe *corev1.Probe `json:"livenessProbe,omitempty"`
	//  Readiness probe
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty"`
}

// Type of deployment
type DeploymentType string

const (
	// CAP backend server deployment type
	DeploymentCAP DeploymentType = "CAP"
	// Application router deployment type
	DeploymentRouter DeploymentType = "Router"
	// Additional deployment type
	DeploymentAdditional DeploymentType = "Additional"
)

// JobDetails specifies the details of the Job
type JobDetails struct {
	ContainerDetails `json:",inline"`
	// Type of Job
	Type JobType `json:"type"`
	// Specifies the number of retries before marking this job failed.
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`
	// Specifies the time after which the job may be cleaned up.
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
}

// Type of Job
type JobType string

const (
	// job for deploying content or configuration to (BTP) services
	JobContent JobType = "Content"
	// job for tenant operation e.g. deploying relevant data to a tenant
	JobTenantOperation JobType = "TenantOperation"
	// job for custom tenant operation e.g. pre/post hooks for a tenant operation
	JobCustomTenantOperation JobType = "CustomTenantOperation"
)

// ContainerDetails specifies the details of the Container
type ContainerDetails struct {
	// Image info for the container
	Image string `json:"image"`
	// Pull policy for the container image
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// Entrypoint array for the container
	Command []string `json:"command,omitempty"`
	// Environment Config for the Container
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Resources
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// SecurityContext for the Container
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
	// SecurityContext for the Pod
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`
}

// Configuration of Service Ports for the deployment
type Ports struct {
	// App protocol used by the service port
	AppProtocol *string `json:"appProtocol,omitempty"`
	// Name of the service port
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=Application;Cluster
	// Network Policy of the service port
	NetworkPolicy PortNetworkPolicyType `json:"networkPolicy,omitempty"`
	// The port number used for container and the corresponding service (if any)
	Port int32 `json:"port"`
	// Destination name which may be used by the Router deployment to reach this backend service
	RouterDestinationName string `json:"routerDestinationName,omitempty"`
}

// Type of NetworkPolicy for the port
type PortNetworkPolicyType string

const (
	// Expose the port for the current application versions pod(s) scope
	PortNetworkPolicyTypeApplication PortNetworkPolicyType = "Application"
	// Expose the port for any pod(s) in the overall cluster scope
	PortNetworkPolicyTypeCluster PortNetworkPolicyType = "Cluster"
)

// Configuration used to sequence tenant related jobs for a given tenant operation
type TenantOperations struct {
	// Tenant provisioning steps
	Provisioning []TenantOperationWorkloadReference `json:"provisioning,omitempty"`
	// Tenant upgrade steps
	Upgrade []TenantOperationWorkloadReference `json:"upgrade,omitempty"`
	// Tenant deprovisioning steps
	Deprovisioning []TenantOperationWorkloadReference `json:"deprovisioning,omitempty"`
}

type TenantOperationWorkloadReference struct {
	// Reference to a specified workload of type 'TenantOperation' or 'CustomTenantOperation'
	WorkloadName string `json:"workloadName"`
	// Indicates whether to proceed with remaining operation steps in case of failure. Relevant only for 'CustomTenantOperation'
	ContinueOnFailure bool `json:"continueOnFailure,omitempty"`
}

// +kubebuilder:resource:shortName=cat
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Current Version",type="string",JSONPath=".status.currentCAPApplicationVersionInstance"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenant defines the schema for captenants API
type CAPTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPTenant spec
	Spec CAPTenantSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPTenant status
	Status CAPTenantStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenantList contains a list of CAPTenant
type CAPTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenant `json:"items"`
}

type CAPTenantStatus struct {
	GenericStatus `json:",inline"`
	// +kubebuilder:validation:Enum="";Ready;Provisioning;Upgrading;Deleting;ProvisioningError;UpgradeError
	// State of CAPTenant
	State CAPTenantState `json:"state"`
	// Specifies the current version of the tenant after provisioning or upgrade
	CurrentCAPApplicationVersionInstance string `json:"currentCAPApplicationVersionInstance,omitempty"`
	// Previous versions of the tenant (first to last)
	PreviousCAPApplicationVersions []string `json:"previousCAPApplicationVersions,omitempty"`
	// The last time a full reconciliation was completed
	LastFullReconciliationTime metav1.Time `json:"lastFullReconciliationTime,omitempty"`
}

type CAPTenantState string

const (
	// Tenant is being provisioned
	CAPTenantStateProvisioning CAPTenantState = "Provisioning"
	// Tenant provisioning ended in error
	CAPTenantStateProvisioningError CAPTenantState = "ProvisioningError"
	// Tenant is being upgraded
	CAPTenantStateUpgrading CAPTenantState = "Upgrading"
	// Tenant upgrade failed
	CAPTenantStateUpgradeError CAPTenantState = "UpgradeError"
	// Deletion has been triggered
	CAPTenantStateDeleting CAPTenantState = "Deleting"
	// Tenant has been provisioned/upgraded and is now ready for use
	CAPTenantStateReady CAPTenantState = "Ready"
)

// CAPTenantSpec defines the desired state of the CAPTenant
type CAPTenantSpec struct {
	// Denotes to which CAPApplication the current tenant belongs
	CAPApplicationInstance string `json:"capApplicationInstance"`
	// Details of consumer sub-account subscribing to the application
	BTPTenantIdentification `json:",inline"`
	// Semver that is used to determine the relevant CAPApplicationVersion that a CAPTenant can be upgraded to (i.e. if it is not already on that version)
	Version string `json:"version,omitempty"`
	// +kubebuilder:validation:Enum=always;never
	// Denotes whether a CAPTenant can be upgraded. One of ('always', 'never')
	VersionUpgradeStrategy VersionUpgradeStrategyType `json:"versionUpgradeStrategy,omitempty"`
}

type VersionUpgradeStrategyType string

const (
	// Always (default)
	VersionUpgradeStrategyTypeAlways VersionUpgradeStrategyType = "always"
	// Never
	VersionUpgradeStrategyTypeNever VersionUpgradeStrategyType = "never"
)

// +kubebuilder:resource:shortName=ctop
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Operation",type="string",JSONPath=".spec.operation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenantOperation defines the schema for captenantoperations API
type CAPTenantOperation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPTenantOperation spec
	Spec CAPTenantOperationSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPTenantOperation status
	Status CAPTenantOperationStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenantOperationList contains a list of CAPTenantOperation
type CAPTenantOperationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenantOperation `json:"items"`
}

type CAPTenantOperationSpec struct {
	// +kubebuilder:validation:Enum=provisioning;deprovisioning;upgrade
	// Scope of the tenant lifecycle operation. One of 'provisioning', 'deprovisioning' or 'upgrade'
	Operation CAPTenantOperationType `json:"operation"`
	// BTP sub-account (tenant) for which request is created
	BTPTenantIdentification `json:",inline"`
	// Reference to CAPApplicationVersion for executing the operation
	CAPApplicationVersionInstance string `json:"capApplicationVersionInstance"`
	// Steps (jobs) to be executed for the operation to complete
	Steps []CAPTenantOperationStep `json:"steps"`
}

type CAPTenantOperationStep struct {
	// Name of the workload from the referenced CAPApplicationVersion
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=CustomTenantOperation;TenantOperation
	// Type of job. One of 'TenantOperation' or 'CustomTenantOperation'
	Type JobType `json:"type"`
	// Indicates whether the operation can continue in case of step failure. Relevant only for type 'CustomTenantOperation'
	ContinueOnFailure bool `json:"continueOnFailure,omitempty"`
}

type CAPTenantOperationStatus struct {
	GenericStatus `json:",inline"`
	// +kubebuilder:validation:Enum="";Processing;Completed;Failed;Deleting
	// State of CAPTenantOperation
	State CAPTenantOperationState `json:"state"`
	// Current step being processed from the sequence of specified steps
	CurrentStep *uint32 `json:"currentStep,omitempty"`
	// Name of the job being executed for the current step
	ActiveJob *string `json:"activeJob,omitempty"`
}

type CAPTenantOperationState string

const (
	// CAPTenantOperation is being processed
	CAPTenantOperationStateProcessing CAPTenantOperationState = "Processing"
	// CAPTenantOperation steps have failed
	CAPTenantOperationStateFailed CAPTenantOperationState = "Failed"
	// CAPTenantOperation steps completed
	CAPTenantOperationStateCompleted CAPTenantOperationState = "Completed"
	// CAPTenantOperation deletion has been triggered
	CAPTenantOperationStateDeleting CAPTenantOperationState = "Deleting"
)

type CAPTenantOperationType string

const (
	// Provision tenant
	CAPTenantOperationTypeProvisioning CAPTenantOperationType = "provisioning"
	// Deprovision tenant
	CAPTenantOperationTypeDeprovisioning CAPTenantOperationType = "deprovisioning"
	// Upgrade tenant
	CAPTenantOperationTypeUpgrade CAPTenantOperationType = "upgrade"
)
