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
	Status v1alpha2.CAPApplicationStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// CAPApplicationList contains a list of CAPApplication
type CAPApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CAPApplication `json:"items"`
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

//Workaround for pattern for string items +kubebuilder:validation:Pattern=^[a-z0-9-.]+$
//type PatternString string

// Generic Name/Value configuration
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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
	Spec v1alpha2.CAPApplicationVersionSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPApplicationVersion status
	Status v1alpha2.CAPApplicationVersionStatus `json:"status"`
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
	Spec v1alpha2.CAPTenantSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPTenant status
	Status v1alpha2.CAPTenantStatus `json:"status"`
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
	Spec v1alpha2.CAPTenantOperationSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// CAPTenantOperation status
	Status v1alpha2.CAPTenantOperationStatus `json:"status"`
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
	Spec v1alpha2.CAPTenantOutputSpec `json:"spec"`
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
	Spec v1alpha2.DomainSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// Domain status
	Status v1alpha2.DomainStatus `json:"status"`
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
	Spec v1alpha2.DomainSpec `json:"spec"`
	// +kubebuilder:validation:Optional
	// ClusterDomain status
	Status v1alpha2.DomainStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Deprecated: sme.sap.com/v1alpha1 is replaced by sme.sap.com/v1alpha2, use the corresponding types/resources from v1alpha2.
// ClusterDomainList contains a list of ClusterDomain
type ClusterDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterDomain `json:"items"`
}
