/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// NameValueApplyConfiguration represents an declarative configuration of the NameValue type for use
// with apply.
type NameValueApplyConfiguration struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

// NameValueApplyConfiguration constructs an declarative configuration of the NameValue type for use with
// apply.
func NameValue() *NameValueApplyConfiguration {
	return &NameValueApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *NameValueApplyConfiguration) WithName(value string) *NameValueApplyConfiguration {
	b.Name = &value
	return b
}

// WithValue sets the Value field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Value field is set to the value of the last call.
func (b *NameValueApplyConfiguration) WithValue(value string) *NameValueApplyConfiguration {
	b.Value = &value
	return b
}
