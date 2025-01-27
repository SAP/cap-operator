/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// CAPApplicationSpecApplyConfiguration represents a declarative configuration of the CAPApplicationSpec type for use
// with apply.
type CAPApplicationSpecApplyConfiguration struct {
	DomainRefs      []DomainRefsApplyConfiguration             `json:"domainRefs,omitempty"`
	Domains         *ApplicationDomainsApplyConfiguration      `json:"domains,omitempty"`
	GlobalAccountId *string                                    `json:"globalAccountId,omitempty"`
	BTPAppName      *string                                    `json:"btpAppName,omitempty"`
	Provider        *BTPTenantIdentificationApplyConfiguration `json:"provider,omitempty"`
	BTP             *BTPApplyConfiguration                     `json:"btp,omitempty"`
}

// CAPApplicationSpecApplyConfiguration constructs a declarative configuration of the CAPApplicationSpec type for use with
// apply.
func CAPApplicationSpec() *CAPApplicationSpecApplyConfiguration {
	return &CAPApplicationSpecApplyConfiguration{}
}

// WithDomainRefs adds the given value to the DomainRefs field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the DomainRefs field.
func (b *CAPApplicationSpecApplyConfiguration) WithDomainRefs(values ...*DomainRefsApplyConfiguration) *CAPApplicationSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithDomainRefs")
		}
		b.DomainRefs = append(b.DomainRefs, *values[i])
	}
	return b
}

// WithDomains sets the Domains field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Domains field is set to the value of the last call.
func (b *CAPApplicationSpecApplyConfiguration) WithDomains(value *ApplicationDomainsApplyConfiguration) *CAPApplicationSpecApplyConfiguration {
	b.Domains = value
	return b
}

// WithGlobalAccountId sets the GlobalAccountId field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GlobalAccountId field is set to the value of the last call.
func (b *CAPApplicationSpecApplyConfiguration) WithGlobalAccountId(value string) *CAPApplicationSpecApplyConfiguration {
	b.GlobalAccountId = &value
	return b
}

// WithBTPAppName sets the BTPAppName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the BTPAppName field is set to the value of the last call.
func (b *CAPApplicationSpecApplyConfiguration) WithBTPAppName(value string) *CAPApplicationSpecApplyConfiguration {
	b.BTPAppName = &value
	return b
}

// WithProvider sets the Provider field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Provider field is set to the value of the last call.
func (b *CAPApplicationSpecApplyConfiguration) WithProvider(value *BTPTenantIdentificationApplyConfiguration) *CAPApplicationSpecApplyConfiguration {
	b.Provider = value
	return b
}

// WithBTP sets the BTP field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the BTP field is set to the value of the last call.
func (b *CAPApplicationSpecApplyConfiguration) WithBTP(value *BTPApplyConfiguration) *CAPApplicationSpecApplyConfiguration {
	b.BTP = value
	return b
}
