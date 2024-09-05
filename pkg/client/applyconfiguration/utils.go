/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package applyconfiguration

import (
	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	internal "github.com/sap/cap-operator/pkg/client/applyconfiguration/internal"
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/client/applyconfiguration/sme.sap.com/v1alpha1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	testing "k8s.io/client-go/testing"
)

// ForKind returns an apply configuration type for the given GroupVersionKind, or nil if no
// apply configuration type exists for the given GroupVersionKind.
func ForKind(kind schema.GroupVersionKind) interface{} {
	switch kind {
	// Group=sme.sap.com, Version=v1alpha1
	case v1alpha1.SchemeGroupVersion.WithKind("ApplicationDomains"):
		return &smesapcomv1alpha1.ApplicationDomainsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("BTP"):
		return &smesapcomv1alpha1.BTPApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("BTPTenantIdentification"):
		return &smesapcomv1alpha1.BTPTenantIdentificationApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplication"):
		return &smesapcomv1alpha1.CAPApplicationApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplicationSpec"):
		return &smesapcomv1alpha1.CAPApplicationSpecApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplicationStatus"):
		return &smesapcomv1alpha1.CAPApplicationStatusApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplicationVersion"):
		return &smesapcomv1alpha1.CAPApplicationVersionApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplicationVersionSpec"):
		return &smesapcomv1alpha1.CAPApplicationVersionSpecApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPApplicationVersionStatus"):
		return &smesapcomv1alpha1.CAPApplicationVersionStatusApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenant"):
		return &smesapcomv1alpha1.CAPTenantApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOperation"):
		return &smesapcomv1alpha1.CAPTenantOperationApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOperationSpec"):
		return &smesapcomv1alpha1.CAPTenantOperationSpecApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOperationStatus"):
		return &smesapcomv1alpha1.CAPTenantOperationStatusApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOperationStep"):
		return &smesapcomv1alpha1.CAPTenantOperationStepApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOutput"):
		return &smesapcomv1alpha1.CAPTenantOutputApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOutputSpec"):
		return &smesapcomv1alpha1.CAPTenantOutputSpecApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantSpec"):
		return &smesapcomv1alpha1.CAPTenantSpecApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CAPTenantStatus"):
		return &smesapcomv1alpha1.CAPTenantStatusApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("CommonDetails"):
		return &smesapcomv1alpha1.CommonDetailsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("DeploymentDetails"):
		return &smesapcomv1alpha1.DeploymentDetailsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("GenericStatus"):
		return &smesapcomv1alpha1.GenericStatusApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("JobDetails"):
		return &smesapcomv1alpha1.JobDetailsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("NameValue"):
		return &smesapcomv1alpha1.NameValueApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("Ports"):
		return &smesapcomv1alpha1.PortsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("ServiceInfo"):
		return &smesapcomv1alpha1.ServiceInfoApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("TenantOperations"):
		return &smesapcomv1alpha1.TenantOperationsApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("TenantOperationWorkloadReference"):
		return &smesapcomv1alpha1.TenantOperationWorkloadReferenceApplyConfiguration{}
	case v1alpha1.SchemeGroupVersion.WithKind("WorkloadDetails"):
		return &smesapcomv1alpha1.WorkloadDetailsApplyConfiguration{}

	}
	return nil
}

func NewTypeConverter(scheme *runtime.Scheme) *testing.TypeConverter {
	return &testing.TypeConverter{Scheme: scheme, TypeResolver: internal.Parser()}
}
