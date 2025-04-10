/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
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
	CAPTenantOutputKind           = "CAPTenantOutput"
	CAPTenantOutputResource       = "captenantouputs"
	DomainKind                    = "Domain"
	DomainResource                = "domains"
	ClusterDomainKind             = "ClusterDomain"
	ClusterDomainResource         = "clusterdomains"
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
	// Represents whether this is a services only scenario
	ServicesOnly *bool `json:"servicesOnly,omitempty"`
	// Hash representing last known application domains
	DomainSpecHash string `json:"domainSpecHash,omitempty"`
	// The last time a full reconciliation was completed
	LastFullReconciliationTime metav1.Time `json:"lastFullReconciliationTime,omitempty"`
	// Last known application subdomains
	ObservedSubdomains []string `json:"observedSubdomains,omitempty"`
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
	// Domains used by the application (new) // TODO: remove optional once the new field is meant to be used
	DomainRefs []DomainRefs `json:"domainRefs,omitempty"`
	// [DEPRECATED] Domains used by the application
	Domains ApplicationDomains `json:"domains,omitempty"`
	// SAP BTP Global Account Identifier where services are entitles for the current application
	GlobalAccountId string `json:"globalAccountId"`
	// Short name for the application (similar to BTP XSAPPNAME)
	BTPAppName string `json:"btpAppName"`
	// Provider subaccount where application services are created
	Provider BTPTenantIdentification `json:"provider,omitempty"`
	// SAP BTP Services consumed by the application
	BTP BTP `json:"btp"`
}

// Domain references
type DomainRefs struct {
	// +kubebuilder:validation:Enum=Domain;ClusterDomain
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Application domains
type ApplicationDomains struct {
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
	// +kubebuilder:validation:MaxLength=62
	// Primary application domain will be used to generate a wildcard TLS certificate. In project "Gardener" managed clusters this is (usually) a subdomain of the cluster domain
	Primary string `json:"primary"`
	// +kubebuilder:validation:items:Pattern=^[a-z0-9-.]+$
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
	// A unique name of service based on usage in the app (this may be the name of the instance or binding)
	Name string `json:"name"`
	// Secret containing service access credentials
	Secret string `json:"secret"`
	// Type of service
	Class string `json:"class"`
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
	// Configuration for the service(s) to be exposed (relevant only for 'Service' type deployment workloads)
	ServiceExposures []ServiceExposure `json:"serviceExposures,omitempty"`
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
	CommonDetails `json:",inline"`
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
	// Workload monitoring specification
	Monitoring *WorkloadMonitoring `json:"monitoring,omitempty"`
}

// ServiceExposure specifies the details of the VirtualService to be exposed for `Service` type workload(s)
type ServiceExposure struct {
	// Subdomain under which the service is exposed (used as the Key for identifying the VirtualService)
	SubDomain string `json:"subDomain"`
	// Routes specifies the routing configuration (http match) for the exposed service
	Routes []Route `json:"routes"`
}

// Routing configuration (http match) for the exposed service
type Route struct {
	// Name of the workload (eventually a service to route requests to); must be a valid workload name (Deployment)
	WorkloadName string `json:"workloadName"`
	// Port number used for the service (must be present in the workload/service)
	Port int32 `json:"port"`
	// A unique routing path used (as a match/prefix) to route requests to the workload (when omitted, "/" would be used)
	Path string `json:"path,omitempty"`
}

// WorkloadMonitoring specifies the metrics related to the workload
type WorkloadMonitoring struct {
	// DeletionRules specify the metrics conditions that need to be satisfied for the version to be deleted automatically.
	// Either a set of metrics based rules can be specified, or a PromQL expression which evaluates to a boolean scalar.
	DeletionRules *DeletionRules `json:"deletionRules,omitempty"`
	// Configuration to be used to create ServiceMonitor for the workload service.
	// If not specified, CAP Operator will not attempt to create a ServiceMonitor for the workload
	ScrapeConfig *MonitoringConfig `json:"scrapeConfig,omitempty"`
}

type MonitoringConfig struct {
	// Interval at which Prometheus scrapes the metrics from the target.
	ScrapeInterval Duration `json:"interval,omitempty"`
	// Name of the port (specified on the workload) which will be used by Prometheus server to scrape metrics
	WorkloadPort string `json:"port"`
	// HTTP path from which to scrape for metrics.
	Path string `json:"path,omitempty"`
	// Timeout after which Prometheus considers the scrape to be failed.
	Timeout Duration `json:"scrapeTimeout,omitempty"`
}

type DeletionRules struct {
	Metrics []MetricRule `json:"metrics,omitempty"`
	// A promQL expression that evaluates to a scalar boolean (1 or 0).
	// Example: scalar(sum(avg_over_time(demo_metric{job="cav-demo-app-4-srv-svc",namespace="demo"}[2m]))) <= bool 0.1
	ScalarExpression *string `json:"expression,omitempty"`
}

// MetricRule specifies a Prometheus metric and rule which represents a cleanup condition. Metrics of type Gauge and Counter are supported.
//
// Rule evaluation for Gauge type metric: The time series data of the metric (restricted to the current workload by setting `job` label as workload service name) is calculated as an average over the specified period.
// A sum of the calculated average from different time series is then compared to the provided threshold value to determine whether the rule has been satisfied.
// Evaluation: `sum(avg_over_time(<gauge-metric>{job=<workload-service-name>}[<lookback-duration>])) <= <lower0threshold-value>`
//
// Rule evaluation for Counter type metric: The time series data of the metric (restricted to the current workload by setting `job` label as workload service name) is calculated as rate of increase over the specified period.
// The sum of the calculated rates from different time series is then compared to the provided threshold value to determine whether the rule has been satisfied.
// Evaluation: `sum(rate(<counter-metric>{job=<workload-service-name>}[<lookback-duration>])) <= <lower0threshold-value>`
type MetricRule struct {
	// Prometheus metric. For example `http_request_count`
	Name string `json:"name"`
	// Type of Prometheus metric which can be either `Gauge` or `Counter`
	// +kubebuilder:validation:Enum=Gauge;Counter
	Type MetricType `json:"type"`
	// Duration of time series data used for the rule evaluation
	CalculationPeriod Duration `json:"calculationPeriod"`
	// The threshold value which is compared against the calculated value. If calculated value is less than or equal to the threshold the rule condition is fulfilled.
	// +kubebuilder:validation:Format:=double
	ThresholdValue string `json:"thresholdValue"`
}

// Duration is a valid time duration that can be parsed by Prometheus
// Supported units: y, w, d, h, m, s, ms
// Examples: `30s`, `1m`, `1h20m15s`, `15d`
// +kubebuilder:validation:Pattern:="^(0|(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?)$"
type Duration string

// Type of Prometheus metric
type MetricType string

const (
	// Prometheus Metric type Gauge
	MetricTypeGauge MetricType = "Gauge"
	// Prometheus Metric type Counter
	MetricTypeCounter MetricType = "Counter"
)

// Type of deployment
type DeploymentType string

const (
	// CAP backend server deployment type
	DeploymentCAP DeploymentType = "CAP"
	// Application router deployment type
	DeploymentRouter DeploymentType = "Router"
	// Additional deployment type
	DeploymentAdditional DeploymentType = "Additional"
	// Service deployment type
	DeploymentService DeploymentType = "Service"
)

// JobDetails specifies the details of the Job
type JobDetails struct {
	CommonDetails `json:",inline"`
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

// CommonDetails specifies the common details of the Container/Pod that may be relevant for both Deployments and Jobs
type CommonDetails struct {
	// Image info for the container
	Image string `json:"image"`
	// Pull policy for the container image
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// Entrypoint array for the container
	Command []string `json:"command,omitempty"`
	// Arguments to the entrypoint
	Args []string `json:"args,omitempty"`
	// Environment Config for the Container
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Volume Configuration for the Pod
	Volumes []corev1.Volume `json:"volumes,omitempty"`
	// Volume Mount Configuration for the Container
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`
	// Name of the ServiceAccount to use to run the Pod
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Resources
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// SecurityContext for the Container
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
	// SecurityContext for the Pod
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`
	// The name of the node to which the Pod should be assigned to. See: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodename
	NodeName string `json:"nodeName,omitempty"`
	// The label selectors using which node for the Pod would be determined. See: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Priority class name mapping used to prioritize and schedule the Pod. See: https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// Affinity/anti-affinity used to provide more constraints for node selection. See: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// Tolerations used to schedule the Pod. See: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// The Topology spread constraints used to control how Pods are spread across regions, zones, nodes etc. See: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#pod-topology-spread-constraints
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// List of containers executed before the main container is started
	InitContainers []corev1.Container `json:"initContainers,omitempty"`
	// Restart policy for the Pod. See: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#restart-policy
	RestartPolicy corev1.RestartPolicy `json:"restartPolicy,omitempty"`
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

// +kubebuilder:resource:shortName=ctout
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenantOutput is the schema for captenantoutputs API
type CAPTenantOutput struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPTenantOutputData spec
	Spec CAPTenantOutputSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CAPTenantOutputList contains a list of CAPTenantOutput
type CAPTenantOutputList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenantOutput `json:"items"`
}

type CAPTenantOutputSpec struct {
	// +kubebuilder:validation:nullable
	SubscriptionCallbackData string `json:"subscriptionCallbackData,omitempty"`
}

// +kubebuilder:resource:shortName=dom
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Domain is the schema for domains API
type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Domains spec
	Spec DomainSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// Domain status
	Status DomainStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DomainList contains a list of Domain
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Domain `json:"items"`
}

type DomainSpec struct {
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
	// Domain used by an application
	Domain string `json:"domain"`
	// Selector is the set of labels used to select the ingress pods handling the domain
	IngressSelector map[string]string `json:"ingressSelector"`
	// +kubebuilder:default:=Simple
	// TLS mode for the generated (Istio) Gateway resource. Set this to Mutual when using mTLS with an external gateway.
	TLSMode TLSMode `json:"tlsMode"`
	// +kubebuilder:default:=None
	// DNS mode controls the creation of DNS entries related to the domain
	DNSMode DNSMode `json:"dnsMode"`
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
	// DNS Target for traffic to this domain
	DNSTarget string `json:"dnsTarget,omitempty"`
}

// +kubebuilder:validation:Enum=Simple;Mutual
type TLSMode string

const (
	// Simple TLS Mode (Default)
	TlsModeSimple TLSMode = "Simple"
	// Mutual TLS Mode
	TlsModeMutual TLSMode = "Mutual"
)

// +kubebuilder:validation:Enum=None;Wildcard;Subdomain
type DNSMode string

const (
	// No DNS entries will be created (Default)
	DnsModeNone DNSMode = "None"
	// Wildcard DNS entry will be created
	DnsModeWildcard DNSMode = "Wildcard"
	// A DNS entry will be created for each subdomain specified by the applications using this domain
	DnsModeSubdomain DNSMode = "Subdomain"
)

type DomainStatus struct {
	GenericStatus `json:",inline"`
	// State of the Domain
	State DomainState `json:"state"`
	// Effective DNS Target identified for this domain
	DnsTarget string `json:"dnsTarget,omitempty"`
	// domain observed during last reconciliation
	ObservedDomain string `json:"observedDomain,omitempty"`
}

// +kubebuilder:validation:Enum="";Ready;Error;Processing;Deleting
type DomainState string

const (
	DomainStateProcessing DomainState = "Processing"
	DomainStateError      DomainState = "Error"
	DomainStateDeleting   DomainState = "Deleting"
	DomainStateReady      DomainState = "Ready"
)

// +kubebuilder:resource:scope=Cluster,shortName=cdom
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterDomain is the schema for clusterdomains API
type ClusterDomain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// ClusterDomains spec
	Spec DomainSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// ClusterDomain status
	Status DomainStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterDomainList contains a list of ClusterDomain
type ClusterDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterDomain `json:"items"`
}
