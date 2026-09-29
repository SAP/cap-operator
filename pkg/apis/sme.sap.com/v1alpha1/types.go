/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
package v1alpha1

import (
	v1alpha2 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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
	CAPTenantOutputResource       = "captenantoutputs"
	DomainKind                    = "Domain"
	DomainResource                = "domains"
	ClusterDomainKind             = "ClusterDomain"
	ClusterDomainResource         = "clusterdomains"
)

// Deprecated: Alias(es) for v1alpha2 types to ensure backward compatibility for v1alpha1 API consumers.
type (

	// Shared / supporting types
	GenericStatus                     = v1alpha2.GenericStatus
	StatusConditionType               = v1alpha2.StatusConditionType
	CAPApplicationStatusConditionType = v1alpha2.CAPApplicationStatusConditionType
	DomainRef                         = v1alpha2.DomainRef
	BTPTenantIdentification           = v1alpha2.BTPTenantIdentification
	BTP                               = v1alpha2.BTP
	ServiceInfo                       = v1alpha2.ServiceInfo
	SubscriptionDependency            = v1alpha2.SubscriptionDependency

	// CAPApplication types
	CAPApplicationStatus = v1alpha2.CAPApplicationStatus
	CAPApplicationState  = v1alpha2.CAPApplicationState

	// CAPApplicationVersion types
	CAPApplicationVersionSpec        = v1alpha2.CAPApplicationVersionSpec
	CAPApplicationVersionStatus      = v1alpha2.CAPApplicationVersionStatus
	CAPApplicationVersionState       = v1alpha2.CAPApplicationVersionState
	WorkloadDetails                  = v1alpha2.WorkloadDetails
	DeploymentDetails                = v1alpha2.DeploymentDetails
	DeploymentType                   = v1alpha2.DeploymentType
	JobDetails                       = v1alpha2.JobDetails
	JobType                          = v1alpha2.JobType
	CommonDetails                    = v1alpha2.CommonDetails
	Ports                            = v1alpha2.Ports
	PortNetworkPolicyType            = v1alpha2.PortNetworkPolicyType
	TenantOperations                 = v1alpha2.TenantOperations
	TenantOperationWorkloadReference = v1alpha2.TenantOperationWorkloadReference
	ServiceExposure                  = v1alpha2.ServiceExposure
	Route                            = v1alpha2.Route
	WorkloadMonitoring               = v1alpha2.WorkloadMonitoring
	MonitoringConfig                 = v1alpha2.MonitoringConfig
	DeletionRules                    = v1alpha2.DeletionRules
	MetricRule                       = v1alpha2.MetricRule
	Duration                         = v1alpha2.Duration
	MetricType                       = v1alpha2.MetricType
	Stickiness                       = v1alpha2.Stickiness
	StickinessHash                   = v1alpha2.StickinessHash
	HTTPCookie                       = v1alpha2.HTTPCookie
	HorizontalPodAutoscalerSpec      = v1alpha2.HorizontalPodAutoscalerSpec

	// CAPTenant types
	CAPTenantSpec              = v1alpha2.CAPTenantSpec
	CAPTenantStatus            = v1alpha2.CAPTenantStatus
	CAPTenantState             = v1alpha2.CAPTenantState
	VersionUpgradeStrategyType = v1alpha2.VersionUpgradeStrategyType

	// CAPTenantOperation types
	CAPTenantOperationSpec   = v1alpha2.CAPTenantOperationSpec
	CAPTenantOperationStatus = v1alpha2.CAPTenantOperationStatus
	CAPTenantOperationStep   = v1alpha2.CAPTenantOperationStep
	CAPTenantOperationState  = v1alpha2.CAPTenantOperationState
	CAPTenantOperationType   = v1alpha2.CAPTenantOperationType

	// CAPTenantOutput types
	CAPTenantOutputSpec = v1alpha2.CAPTenantOutputSpec

	// Domain / ClusterDomain types
	DomainSpec   = v1alpha2.DomainSpec
	DomainStatus = v1alpha2.DomainStatus
	DomainState  = v1alpha2.DomainState
	DNSTemplate  = v1alpha2.DNSTemplate
	CertConfig   = v1alpha2.CertConfig
	CertManager  = v1alpha2.CertManager
	TLSMode      = v1alpha2.TLSMode
	DNSMode      = v1alpha2.DNSMode
)

// +kubebuilder:resource:shortName=ca
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPApplicationList contains a list of CAPApplication
type CAPApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPApplication `json:"items"`
}

// Application domains
//
// Deprecated: ApplicationDomains exists for historical compatibility and should not be used.
// This will be removed in future versions. Use DomainRef instead.
type ApplicationDomains struct {
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
	// +kubebuilder:validation:MaxLength=62
	// Primary application domain will be used to generate a wildcard TLS certificate. In project "Gardener" managed clusters this is (usually) a subdomain of the cluster domain
	Primary string `json:"primary,omitempty"`
	// +kubebuilder:validation:items:Pattern=^[a-z0-9-.]+$
	// Customer specific domains to serve application endpoints (optional)
	Secondary []string `json:"secondary,omitempty"`
	// +kubebuilder:validation:Pattern=^[a-z0-9-.]*$
	// Public ingress URL for the cluster Load Balancer
	DnsTarget string `json:"dnsTarget,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// Labels used to identify the istio ingress-gateway component and its corresponding namespace. Usually {"app":"istio-ingressgateway","istio":"ingressgateway"}
	IstioIngressGatewayLabels []NameValue `json:"istioIngressGatewayLabels,omitempty"`
}

// Generic Name/Value configuration
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPApplicationSpec defines the desired state of CAPApplication
type CAPApplicationSpec struct {
	// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
	v1alpha2.CAPApplicationSpec `json:",inline"`
	// Deprecated: Domains used by the application. Will be removed in future versions, use `DomainRefs` instead
	Domains ApplicationDomains `json:"domains,omitempty"`
	// Deprecated: SAP BTP Global Account Identifier where services are entitled for the current application
	// Will be removed soon, use ProviderSubaccountId instead
	GlobalAccountId string `json:"globalAccountId,omitempty"`
}

// +kubebuilder:resource:shortName=cav
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPApplicationVersionList contains a list of CAPApplicationVersion
type CAPApplicationVersionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPApplicationVersion `json:"items"`
}

// +kubebuilder:resource:shortName=cat
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Subdomain",type="string",JSONPath=".spec.subDomain"
// +kubebuilder:printcolumn:name="Current Version",type="string",JSONPath=".status.currentCAPApplicationVersionInstance"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPTenantList contains a list of CAPTenant
type CAPTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenant `json:"items"`
}

// +kubebuilder:resource:shortName=ctop
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Operation",type="string",JSONPath=".spec.operation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPTenantOperationList contains a list of CAPTenantOperation
type CAPTenantOperationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenantOperation `json:"items"`
}

// +kubebuilder:resource:shortName=ctout
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPTenantOutput is the schema for captenantoutputs API
type CAPTenantOutput struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// CAPTenantOutput spec
	Spec CAPTenantOutputSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPTenantOutputList contains a list of CAPTenantOutput
type CAPTenantOutputList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPTenantOutput `json:"items"`
}

// +kubebuilder:resource:shortName=dom
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// DomainList contains a list of Domain
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Domain `json:"items"`
}

// +kubebuilder:resource:scope=Cluster,shortName=cdom
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
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

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// ClusterDomainList contains a list of ClusterDomain
type ClusterDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterDomain `json:"items"`
}
