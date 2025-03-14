/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

// DomainRefsApplyConfiguration represents a declarative configuration of the DomainRefs type for use
// with apply.
type DomainRefsApplyConfiguration struct {
	Kind *smesapcomv1alpha1.DomainType `json:"kind,omitempty"`
	Name *string                       `json:"name,omitempty"`
}

// DomainRefsApplyConfiguration constructs a declarative configuration of the DomainRefs type for use with
// apply.
func DomainRefs() *DomainRefsApplyConfiguration {
	return &DomainRefsApplyConfiguration{}
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *DomainRefsApplyConfiguration) WithKind(value smesapcomv1alpha1.DomainType) *DomainRefsApplyConfiguration {
	b.Kind = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *DomainRefsApplyConfiguration) WithName(value string) *DomainRefsApplyConfiguration {
	b.Name = &value
	return b
}
