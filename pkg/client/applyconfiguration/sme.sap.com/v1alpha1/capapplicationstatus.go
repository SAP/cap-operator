/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// CAPApplicationStatusApplyConfiguration represents a declarative configuration of the CAPApplicationStatus type for use
// with apply.
type CAPApplicationStatusApplyConfiguration struct {
	GenericStatusApplyConfiguration `json:",inline"`
	State                           *smesapcomv1alpha1.CAPApplicationState `json:"state,omitempty"`
	DomainSpecHash                  *string                                `json:"domainSpecHash,omitempty"`
	LastFullReconciliationTime      *v1.Time                               `json:"lastFullReconciliationTime,omitempty"`
}

// CAPApplicationStatusApplyConfiguration constructs a declarative configuration of the CAPApplicationStatus type for use with
// apply.
func CAPApplicationStatus() *CAPApplicationStatusApplyConfiguration {
	return &CAPApplicationStatusApplyConfiguration{}
}

// WithObservedGeneration sets the ObservedGeneration field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ObservedGeneration field is set to the value of the last call.
func (b *CAPApplicationStatusApplyConfiguration) WithObservedGeneration(value int64) *CAPApplicationStatusApplyConfiguration {
	b.GenericStatusApplyConfiguration.ObservedGeneration = &value
	return b
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *CAPApplicationStatusApplyConfiguration) WithConditions(values ...*metav1.ConditionApplyConfiguration) *CAPApplicationStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.GenericStatusApplyConfiguration.Conditions = append(b.GenericStatusApplyConfiguration.Conditions, *values[i])
	}
	return b
}

// WithState sets the State field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the State field is set to the value of the last call.
func (b *CAPApplicationStatusApplyConfiguration) WithState(value smesapcomv1alpha1.CAPApplicationState) *CAPApplicationStatusApplyConfiguration {
	b.State = &value
	return b
}

// WithDomainSpecHash sets the DomainSpecHash field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DomainSpecHash field is set to the value of the last call.
func (b *CAPApplicationStatusApplyConfiguration) WithDomainSpecHash(value string) *CAPApplicationStatusApplyConfiguration {
	b.DomainSpecHash = &value
	return b
}

// WithLastFullReconciliationTime sets the LastFullReconciliationTime field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LastFullReconciliationTime field is set to the value of the last call.
func (b *CAPApplicationStatusApplyConfiguration) WithLastFullReconciliationTime(value v1.Time) *CAPApplicationStatusApplyConfiguration {
	b.LastFullReconciliationTime = &value
	return b
}
