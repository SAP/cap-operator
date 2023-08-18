/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/exp/slices"
)

const (
	AnnotationPrimaryXSUAA = "sme.sap.com/primary-xsuaa"
)

func GetXSUAAInfo(consumedServiceInfos []v1alpha1.ServiceInfo, ca *v1alpha1.CAPApplication) *v1alpha1.ServiceInfo {
	// Get primary xsuaa service instance name
	primaryXSUAA := ca.Annotations[AnnotationPrimaryXSUAA]

	serviceIndex := -1

	// Check if matching service with annotated xsuaa name exists
	if primaryXSUAA != "" {
		serviceIndex = slices.IndexFunc(consumedServiceInfos, func(consumedServiceInfo v1alpha1.ServiceInfo) bool {
			return consumedServiceInfo.Name == primaryXSUAA
		})
	}

	// Fallback to using 1st matching "xsuaa" class in the list of consumed services
	if serviceIndex == -1 {
		serviceIndex = slices.IndexFunc(consumedServiceInfos, func(consumedServiceInfo v1alpha1.ServiceInfo) bool { return consumedServiceInfo.Class == "xsuaa" })
	}

	// Return matching service info if any
	if serviceIndex > -1 {
		return &consumedServiceInfos[serviceIndex]
	}

	return nil
}
