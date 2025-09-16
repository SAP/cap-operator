/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

var (
	// SchemeBuilder initializes a scheme builder
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme is a global function that registers this API group & version to a scheme
	AddToScheme = SchemeBuilder.AddToScheme
)

// Kind takes an unqualified kind and returns back a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// Adds the list of known types to the given scheme
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&CAPApplication{},
		&CAPApplicationList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&CAPApplicationVersion{},
		&CAPApplicationVersionList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&CAPTenant{},
		&CAPTenantList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&CAPTenantOperation{},
		&CAPTenantOperationList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&CAPTenantOutput{},
		&CAPTenantOutputList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&Domain{},
		&DomainList{},
	)
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&ClusterDomain{},
		&ClusterDomainList{},
	)
	metaV1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
