/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

// CAPTenantSpecApplyConfiguration represents a declarative configuration of the CAPTenantSpec type for use
// with apply.
type CAPTenantSpecApplyConfiguration struct {
	CAPApplicationInstance                    *string `json:"capApplicationInstance,omitempty"`
	BTPTenantIdentificationApplyConfiguration `json:",inline"`
	Version                                   *string                                       `json:"version,omitempty"`
	VersionUpgradeStrategy                    *smesapcomv1alpha1.VersionUpgradeStrategyType `json:"versionUpgradeStrategy,omitempty"`
}

// CAPTenantSpecApplyConfiguration constructs a declarative configuration of the CAPTenantSpec type for use with
// apply.
func CAPTenantSpec() *CAPTenantSpecApplyConfiguration {
	return &CAPTenantSpecApplyConfiguration{}
}

// WithCAPApplicationInstance sets the CAPApplicationInstance field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CAPApplicationInstance field is set to the value of the last call.
func (b *CAPTenantSpecApplyConfiguration) WithCAPApplicationInstance(value string) *CAPTenantSpecApplyConfiguration {
	b.CAPApplicationInstance = &value
	return b
}

// WithSubDomain sets the SubDomain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SubDomain field is set to the value of the last call.
func (b *CAPTenantSpecApplyConfiguration) WithSubDomain(value string) *CAPTenantSpecApplyConfiguration {
	b.BTPTenantIdentificationApplyConfiguration.SubDomain = &value
	return b
}

// WithTenantId sets the TenantId field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TenantId field is set to the value of the last call.
func (b *CAPTenantSpecApplyConfiguration) WithTenantId(value string) *CAPTenantSpecApplyConfiguration {
	b.BTPTenantIdentificationApplyConfiguration.TenantId = &value
	return b
}

// WithVersion sets the Version field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Version field is set to the value of the last call.
func (b *CAPTenantSpecApplyConfiguration) WithVersion(value string) *CAPTenantSpecApplyConfiguration {
	b.Version = &value
	return b
}

// WithVersionUpgradeStrategy sets the VersionUpgradeStrategy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the VersionUpgradeStrategy field is set to the value of the last call.
func (b *CAPTenantSpecApplyConfiguration) WithVersionUpgradeStrategy(value smesapcomv1alpha1.VersionUpgradeStrategyType) *CAPTenantSpecApplyConfiguration {
	b.VersionUpgradeStrategy = &value
	return b
}
