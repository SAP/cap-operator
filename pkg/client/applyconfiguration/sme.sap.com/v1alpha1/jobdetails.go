/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	v1 "k8s.io/api/core/v1"
)

// JobDetailsApplyConfiguration represents a declarative configuration of the JobDetails type for use
// with apply.
type JobDetailsApplyConfiguration struct {
	CommonDetailsApplyConfiguration `json:",inline"`
	Type                            *smesapcomv1alpha1.JobType `json:"type,omitempty"`
	BackoffLimit                    *int32                     `json:"backoffLimit,omitempty"`
	TTLSecondsAfterFinished         *int32                     `json:"ttlSecondsAfterFinished,omitempty"`
}

// JobDetailsApplyConfiguration constructs a declarative configuration of the JobDetails type for use with
// apply.
func JobDetails() *JobDetailsApplyConfiguration {
	return &JobDetailsApplyConfiguration{}
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithImage(value string) *JobDetailsApplyConfiguration {
	b.Image = &value
	return b
}

// WithImagePullPolicy sets the ImagePullPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ImagePullPolicy field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithImagePullPolicy(value v1.PullPolicy) *JobDetailsApplyConfiguration {
	b.ImagePullPolicy = &value
	return b
}

// WithCommand adds the given value to the Command field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Command field.
func (b *JobDetailsApplyConfiguration) WithCommand(values ...string) *JobDetailsApplyConfiguration {
	for i := range values {
		b.Command = append(b.Command, values[i])
	}
	return b
}

// WithEnv adds the given value to the Env field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Env field.
func (b *JobDetailsApplyConfiguration) WithEnv(values ...v1.EnvVar) *JobDetailsApplyConfiguration {
	for i := range values {
		b.Env = append(b.Env, values[i])
	}
	return b
}

// WithVolumes adds the given value to the Volumes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Volumes field.
func (b *JobDetailsApplyConfiguration) WithVolumes(values ...v1.Volume) *JobDetailsApplyConfiguration {
	for i := range values {
		b.Volumes = append(b.Volumes, values[i])
	}
	return b
}

// WithVolumeMounts adds the given value to the VolumeMounts field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the VolumeMounts field.
func (b *JobDetailsApplyConfiguration) WithVolumeMounts(values ...v1.VolumeMount) *JobDetailsApplyConfiguration {
	for i := range values {
		b.VolumeMounts = append(b.VolumeMounts, values[i])
	}
	return b
}

// WithServiceAccountName sets the ServiceAccountName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountName field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithServiceAccountName(value string) *JobDetailsApplyConfiguration {
	b.ServiceAccountName = &value
	return b
}

// WithResources sets the Resources field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Resources field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithResources(value v1.ResourceRequirements) *JobDetailsApplyConfiguration {
	b.Resources = &value
	return b
}

// WithSecurityContext sets the SecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecurityContext field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithSecurityContext(value v1.SecurityContext) *JobDetailsApplyConfiguration {
	b.SecurityContext = &value
	return b
}

// WithPodSecurityContext sets the PodSecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodSecurityContext field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithPodSecurityContext(value v1.PodSecurityContext) *JobDetailsApplyConfiguration {
	b.PodSecurityContext = &value
	return b
}

// WithNodeName sets the NodeName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NodeName field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithNodeName(value string) *JobDetailsApplyConfiguration {
	b.NodeName = &value
	return b
}

// WithNodeSelector puts the entries into the NodeSelector field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the NodeSelector field,
// overwriting an existing map entries in NodeSelector field with the same key.
func (b *JobDetailsApplyConfiguration) WithNodeSelector(entries map[string]string) *JobDetailsApplyConfiguration {
	if b.NodeSelector == nil && len(entries) > 0 {
		b.NodeSelector = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.NodeSelector[k] = v
	}
	return b
}

// WithPriorityClassName sets the PriorityClassName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PriorityClassName field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithPriorityClassName(value string) *JobDetailsApplyConfiguration {
	b.PriorityClassName = &value
	return b
}

// WithAffinity sets the Affinity field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Affinity field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithAffinity(value v1.Affinity) *JobDetailsApplyConfiguration {
	b.Affinity = &value
	return b
}

// WithTolerations adds the given value to the Tolerations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Tolerations field.
func (b *JobDetailsApplyConfiguration) WithTolerations(values ...v1.Toleration) *JobDetailsApplyConfiguration {
	for i := range values {
		b.Tolerations = append(b.Tolerations, values[i])
	}
	return b
}

// WithTopologySpreadConstraints adds the given value to the TopologySpreadConstraints field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the TopologySpreadConstraints field.
func (b *JobDetailsApplyConfiguration) WithTopologySpreadConstraints(values ...v1.TopologySpreadConstraint) *JobDetailsApplyConfiguration {
	for i := range values {
		b.TopologySpreadConstraints = append(b.TopologySpreadConstraints, values[i])
	}
	return b
}

// WithInitContainers adds the given value to the InitContainers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the InitContainers field.
func (b *JobDetailsApplyConfiguration) WithInitContainers(values ...v1.Container) *JobDetailsApplyConfiguration {
	for i := range values {
		b.InitContainers = append(b.InitContainers, values[i])
	}
	return b
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithType(value smesapcomv1alpha1.JobType) *JobDetailsApplyConfiguration {
	b.Type = &value
	return b
}

// WithBackoffLimit sets the BackoffLimit field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the BackoffLimit field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithBackoffLimit(value int32) *JobDetailsApplyConfiguration {
	b.BackoffLimit = &value
	return b
}

// WithTTLSecondsAfterFinished sets the TTLSecondsAfterFinished field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TTLSecondsAfterFinished field is set to the value of the last call.
func (b *JobDetailsApplyConfiguration) WithTTLSecondsAfterFinished(value int32) *JobDetailsApplyConfiguration {
	b.TTLSecondsAfterFinished = &value
	return b
}
