/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
)

// CommonDetailsApplyConfiguration represents a declarative configuration of the CommonDetails type for use
// with apply.
type CommonDetailsApplyConfiguration struct {
	Image                     *string                       `json:"image,omitempty"`
	ImagePullPolicy           *v1.PullPolicy                `json:"imagePullPolicy,omitempty"`
	Command                   []string                      `json:"command,omitempty"`
	Args                      []string                      `json:"args,omitempty"`
	Env                       []v1.EnvVar                   `json:"env,omitempty"`
	Volumes                   []v1.Volume                   `json:"volumes,omitempty"`
	VolumeMounts              []v1.VolumeMount              `json:"volumeMounts,omitempty"`
	ServiceAccountName        *string                       `json:"serviceAccountName,omitempty"`
	Resources                 *v1.ResourceRequirements      `json:"resources,omitempty"`
	SecurityContext           *v1.SecurityContext           `json:"securityContext,omitempty"`
	PodSecurityContext        *v1.PodSecurityContext        `json:"podSecurityContext,omitempty"`
	NodeName                  *string                       `json:"nodeName,omitempty"`
	NodeSelector              map[string]string             `json:"nodeSelector,omitempty"`
	PriorityClassName         *string                       `json:"priorityClassName,omitempty"`
	Affinity                  *v1.Affinity                  `json:"affinity,omitempty"`
	Tolerations               []v1.Toleration               `json:"tolerations,omitempty"`
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	InitContainers            []v1.Container                `json:"initContainers,omitempty"`
	RestartPolicy             *v1.RestartPolicy             `json:"restartPolicy,omitempty"`
}

// CommonDetailsApplyConfiguration constructs a declarative configuration of the CommonDetails type for use with
// apply.
func CommonDetails() *CommonDetailsApplyConfiguration {
	return &CommonDetailsApplyConfiguration{}
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithImage(value string) *CommonDetailsApplyConfiguration {
	b.Image = &value
	return b
}

// WithImagePullPolicy sets the ImagePullPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ImagePullPolicy field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithImagePullPolicy(value v1.PullPolicy) *CommonDetailsApplyConfiguration {
	b.ImagePullPolicy = &value
	return b
}

// WithCommand adds the given value to the Command field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Command field.
func (b *CommonDetailsApplyConfiguration) WithCommand(values ...string) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.Command = append(b.Command, values[i])
	}
	return b
}

// WithArgs adds the given value to the Args field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Args field.
func (b *CommonDetailsApplyConfiguration) WithArgs(values ...string) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.Args = append(b.Args, values[i])
	}
	return b
}

// WithEnv adds the given value to the Env field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Env field.
func (b *CommonDetailsApplyConfiguration) WithEnv(values ...v1.EnvVar) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.Env = append(b.Env, values[i])
	}
	return b
}

// WithVolumes adds the given value to the Volumes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Volumes field.
func (b *CommonDetailsApplyConfiguration) WithVolumes(values ...v1.Volume) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.Volumes = append(b.Volumes, values[i])
	}
	return b
}

// WithVolumeMounts adds the given value to the VolumeMounts field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the VolumeMounts field.
func (b *CommonDetailsApplyConfiguration) WithVolumeMounts(values ...v1.VolumeMount) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.VolumeMounts = append(b.VolumeMounts, values[i])
	}
	return b
}

// WithServiceAccountName sets the ServiceAccountName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountName field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithServiceAccountName(value string) *CommonDetailsApplyConfiguration {
	b.ServiceAccountName = &value
	return b
}

// WithResources sets the Resources field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Resources field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithResources(value v1.ResourceRequirements) *CommonDetailsApplyConfiguration {
	b.Resources = &value
	return b
}

// WithSecurityContext sets the SecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecurityContext field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithSecurityContext(value v1.SecurityContext) *CommonDetailsApplyConfiguration {
	b.SecurityContext = &value
	return b
}

// WithPodSecurityContext sets the PodSecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodSecurityContext field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithPodSecurityContext(value v1.PodSecurityContext) *CommonDetailsApplyConfiguration {
	b.PodSecurityContext = &value
	return b
}

// WithNodeName sets the NodeName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NodeName field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithNodeName(value string) *CommonDetailsApplyConfiguration {
	b.NodeName = &value
	return b
}

// WithNodeSelector puts the entries into the NodeSelector field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the NodeSelector field,
// overwriting an existing map entries in NodeSelector field with the same key.
func (b *CommonDetailsApplyConfiguration) WithNodeSelector(entries map[string]string) *CommonDetailsApplyConfiguration {
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
func (b *CommonDetailsApplyConfiguration) WithPriorityClassName(value string) *CommonDetailsApplyConfiguration {
	b.PriorityClassName = &value
	return b
}

// WithAffinity sets the Affinity field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Affinity field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithAffinity(value v1.Affinity) *CommonDetailsApplyConfiguration {
	b.Affinity = &value
	return b
}

// WithTolerations adds the given value to the Tolerations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Tolerations field.
func (b *CommonDetailsApplyConfiguration) WithTolerations(values ...v1.Toleration) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.Tolerations = append(b.Tolerations, values[i])
	}
	return b
}

// WithTopologySpreadConstraints adds the given value to the TopologySpreadConstraints field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the TopologySpreadConstraints field.
func (b *CommonDetailsApplyConfiguration) WithTopologySpreadConstraints(values ...v1.TopologySpreadConstraint) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.TopologySpreadConstraints = append(b.TopologySpreadConstraints, values[i])
	}
	return b
}

// WithInitContainers adds the given value to the InitContainers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the InitContainers field.
func (b *CommonDetailsApplyConfiguration) WithInitContainers(values ...v1.Container) *CommonDetailsApplyConfiguration {
	for i := range values {
		b.InitContainers = append(b.InitContainers, values[i])
	}
	return b
}

// WithRestartPolicy sets the RestartPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RestartPolicy field is set to the value of the last call.
func (b *CommonDetailsApplyConfiguration) WithRestartPolicy(value v1.RestartPolicy) *CommonDetailsApplyConfiguration {
	b.RestartPolicy = &value
	return b
}
