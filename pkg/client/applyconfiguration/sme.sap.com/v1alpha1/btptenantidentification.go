/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// BTPTenantIdentificationApplyConfiguration represents an declarative configuration of the BTPTenantIdentification type for use
// with apply.
type BTPTenantIdentificationApplyConfiguration struct {
	SubDomain *string `json:"subDomain,omitempty"`
	TenantId  *string `json:"tenantId,omitempty"`
}

// BTPTenantIdentificationApplyConfiguration constructs an declarative configuration of the BTPTenantIdentification type for use with
// apply.
func BTPTenantIdentification() *BTPTenantIdentificationApplyConfiguration {
	return &BTPTenantIdentificationApplyConfiguration{}
}

// WithSubDomain sets the SubDomain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SubDomain field is set to the value of the last call.
func (b *BTPTenantIdentificationApplyConfiguration) WithSubDomain(value string) *BTPTenantIdentificationApplyConfiguration {
	b.SubDomain = &value
	return b
}

// WithTenantId sets the TenantId field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TenantId field is set to the value of the last call.
func (b *BTPTenantIdentificationApplyConfiguration) WithTenantId(value string) *BTPTenantIdentificationApplyConfiguration {
	b.TenantId = &value
	return b
}
