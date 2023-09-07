/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

// PortsApplyConfiguration represents an declarative configuration of the Ports type for use
// with apply.
type PortsApplyConfiguration struct {
	AppProtocol           *string                         `json:"appProtocol,omitempty"`
	Name                  *string                         `json:"name,omitempty"`
	NetworkPolicy         *v1alpha1.PortNetworkPolicyType `json:"networkPolicy,omitempty"`
	Port                  *int32                          `json:"port,omitempty"`
	RouterDestinationName *string                         `json:"routerDestinationName,omitempty"`
}

// PortsApplyConfiguration constructs an declarative configuration of the Ports type for use with
// apply.
func Ports() *PortsApplyConfiguration {
	return &PortsApplyConfiguration{}
}

// WithAppProtocol sets the AppProtocol field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the AppProtocol field is set to the value of the last call.
func (b *PortsApplyConfiguration) WithAppProtocol(value string) *PortsApplyConfiguration {
	b.AppProtocol = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *PortsApplyConfiguration) WithName(value string) *PortsApplyConfiguration {
	b.Name = &value
	return b
}

// WithNetworkPolicy sets the NetworkPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NetworkPolicy field is set to the value of the last call.
func (b *PortsApplyConfiguration) WithNetworkPolicy(value v1alpha1.PortNetworkPolicyType) *PortsApplyConfiguration {
	b.NetworkPolicy = &value
	return b
}

// WithPort sets the Port field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Port field is set to the value of the last call.
func (b *PortsApplyConfiguration) WithPort(value int32) *PortsApplyConfiguration {
	b.Port = &value
	return b
}

// WithRouterDestinationName sets the RouterDestinationName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RouterDestinationName field is set to the value of the last call.
func (b *PortsApplyConfiguration) WithRouterDestinationName(value string) *PortsApplyConfiguration {
	b.RouterDestinationName = &value
	return b
}
