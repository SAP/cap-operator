/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

// DomainSpecApplyConfiguration represents a declarative configuration of the DomainSpec type for use
// with apply.
type DomainSpecApplyConfiguration struct {
	Domain          *string                       `json:"domain,omitempty"`
	IngressSelector map[string]string             `json:"ingressSelector,omitempty"`
	TLSMode         *smesapcomv1alpha1.TLSMode    `json:"tlsMode,omitempty"`
	DNSMode         *smesapcomv1alpha1.DNSMode    `json:"dnsMode,omitempty"`
	DNSTarget       *string                       `json:"dnsTarget,omitempty"`
	CertConfig      *CertConfigApplyConfiguration `json:"certConfig,omitempty"`
}

// DomainSpecApplyConfiguration constructs a declarative configuration of the DomainSpec type for use with
// apply.
func DomainSpec() *DomainSpecApplyConfiguration {
	return &DomainSpecApplyConfiguration{}
}

// WithDomain sets the Domain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Domain field is set to the value of the last call.
func (b *DomainSpecApplyConfiguration) WithDomain(value string) *DomainSpecApplyConfiguration {
	b.Domain = &value
	return b
}

// WithIngressSelector puts the entries into the IngressSelector field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the IngressSelector field,
// overwriting an existing map entries in IngressSelector field with the same key.
func (b *DomainSpecApplyConfiguration) WithIngressSelector(entries map[string]string) *DomainSpecApplyConfiguration {
	if b.IngressSelector == nil && len(entries) > 0 {
		b.IngressSelector = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.IngressSelector[k] = v
	}
	return b
}

// WithTLSMode sets the TLSMode field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSMode field is set to the value of the last call.
func (b *DomainSpecApplyConfiguration) WithTLSMode(value smesapcomv1alpha1.TLSMode) *DomainSpecApplyConfiguration {
	b.TLSMode = &value
	return b
}

// WithDNSMode sets the DNSMode field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DNSMode field is set to the value of the last call.
func (b *DomainSpecApplyConfiguration) WithDNSMode(value smesapcomv1alpha1.DNSMode) *DomainSpecApplyConfiguration {
	b.DNSMode = &value
	return b
}

// WithDNSTarget sets the DNSTarget field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DNSTarget field is set to the value of the last call.
func (b *DomainSpecApplyConfiguration) WithDNSTarget(value string) *DomainSpecApplyConfiguration {
	b.DNSTarget = &value
	return b
}

// WithCertConfig sets the CertConfig field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CertConfig field is set to the value of the last call.
func (b *DomainSpecApplyConfiguration) WithCertConfig(value *CertConfigApplyConfiguration) *DomainSpecApplyConfiguration {
	b.CertConfig = value
	return b
}
