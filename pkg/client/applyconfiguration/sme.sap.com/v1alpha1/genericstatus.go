/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// GenericStatusApplyConfiguration represents a declarative configuration of the GenericStatus type for use
// with apply.
type GenericStatusApplyConfiguration struct {
	ObservedGeneration *int64                           `json:"observedGeneration,omitempty"`
	Conditions         []v1.ConditionApplyConfiguration `json:"conditions,omitempty"`
}

// GenericStatusApplyConfiguration constructs a declarative configuration of the GenericStatus type for use with
// apply.
func GenericStatus() *GenericStatusApplyConfiguration {
	return &GenericStatusApplyConfiguration{}
}

// WithObservedGeneration sets the ObservedGeneration field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ObservedGeneration field is set to the value of the last call.
func (b *GenericStatusApplyConfiguration) WithObservedGeneration(value int64) *GenericStatusApplyConfiguration {
	b.ObservedGeneration = &value
	return b
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *GenericStatusApplyConfiguration) WithConditions(values ...*v1.ConditionApplyConfiguration) *GenericStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.Conditions = append(b.Conditions, *values[i])
	}
	return b
}
