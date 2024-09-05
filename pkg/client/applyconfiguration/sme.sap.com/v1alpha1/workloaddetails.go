/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// WorkloadDetailsApplyConfiguration represents a declarative configuration of the WorkloadDetails type for use
// with apply.
type WorkloadDetailsApplyConfiguration struct {
	Name                 *string                              `json:"name,omitempty"`
	ConsumedBTPServices  []string                             `json:"consumedBTPServices,omitempty"`
	Labels               map[string]string                    `json:"labels,omitempty"`
	Annotations          map[string]string                    `json:"annotations,omitempty"`
	DeploymentDefinition *DeploymentDetailsApplyConfiguration `json:"deploymentDefinition,omitempty"`
	JobDefinition        *JobDetailsApplyConfiguration        `json:"jobDefinition,omitempty"`
}

// WorkloadDetailsApplyConfiguration constructs a declarative configuration of the WorkloadDetails type for use with
// apply.
func WorkloadDetails() *WorkloadDetailsApplyConfiguration {
	return &WorkloadDetailsApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *WorkloadDetailsApplyConfiguration) WithName(value string) *WorkloadDetailsApplyConfiguration {
	b.Name = &value
	return b
}

// WithConsumedBTPServices adds the given value to the ConsumedBTPServices field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ConsumedBTPServices field.
func (b *WorkloadDetailsApplyConfiguration) WithConsumedBTPServices(values ...string) *WorkloadDetailsApplyConfiguration {
	for i := range values {
		b.ConsumedBTPServices = append(b.ConsumedBTPServices, values[i])
	}
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *WorkloadDetailsApplyConfiguration) WithLabels(entries map[string]string) *WorkloadDetailsApplyConfiguration {
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *WorkloadDetailsApplyConfiguration) WithAnnotations(entries map[string]string) *WorkloadDetailsApplyConfiguration {
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithDeploymentDefinition sets the DeploymentDefinition field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeploymentDefinition field is set to the value of the last call.
func (b *WorkloadDetailsApplyConfiguration) WithDeploymentDefinition(value *DeploymentDetailsApplyConfiguration) *WorkloadDetailsApplyConfiguration {
	b.DeploymentDefinition = value
	return b
}

// WithJobDefinition sets the JobDefinition field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the JobDefinition field is set to the value of the last call.
func (b *WorkloadDetailsApplyConfiguration) WithJobDefinition(value *JobDetailsApplyConfiguration) *WorkloadDetailsApplyConfiguration {
	b.JobDefinition = value
	return b
}
