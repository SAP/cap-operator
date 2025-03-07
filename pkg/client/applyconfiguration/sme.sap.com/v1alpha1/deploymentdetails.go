/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	v1 "k8s.io/api/core/v1"
)

// DeploymentDetailsApplyConfiguration represents a declarative configuration of the DeploymentDetails type for use
// with apply.
type DeploymentDetailsApplyConfiguration struct {
	CommonDetailsApplyConfiguration `json:",inline"`
	Type                            *smesapcomv1alpha1.DeploymentType     `json:"type,omitempty"`
	Replicas                        *int32                                `json:"replicas,omitempty"`
	Ports                           []PortsApplyConfiguration             `json:"ports,omitempty"`
	LivenessProbe                   *v1.Probe                             `json:"livenessProbe,omitempty"`
	ReadinessProbe                  *v1.Probe                             `json:"readinessProbe,omitempty"`
	Monitoring                      *WorkloadMonitoringApplyConfiguration `json:"monitoring,omitempty"`
}

// DeploymentDetailsApplyConfiguration constructs a declarative configuration of the DeploymentDetails type for use with
// apply.
func DeploymentDetails() *DeploymentDetailsApplyConfiguration {
	return &DeploymentDetailsApplyConfiguration{}
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithImage(value string) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.Image = &value
	return b
}

// WithImagePullPolicy sets the ImagePullPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ImagePullPolicy field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithImagePullPolicy(value v1.PullPolicy) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.ImagePullPolicy = &value
	return b
}

// WithCommand adds the given value to the Command field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Command field.
func (b *DeploymentDetailsApplyConfiguration) WithCommand(values ...string) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.Command = append(b.CommonDetailsApplyConfiguration.Command, values[i])
	}
	return b
}

// WithArgs adds the given value to the Args field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Args field.
func (b *DeploymentDetailsApplyConfiguration) WithArgs(values ...string) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.Args = append(b.CommonDetailsApplyConfiguration.Args, values[i])
	}
	return b
}

// WithEnv adds the given value to the Env field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Env field.
func (b *DeploymentDetailsApplyConfiguration) WithEnv(values ...v1.EnvVar) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.Env = append(b.CommonDetailsApplyConfiguration.Env, values[i])
	}
	return b
}

// WithVolumes adds the given value to the Volumes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Volumes field.
func (b *DeploymentDetailsApplyConfiguration) WithVolumes(values ...v1.Volume) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.Volumes = append(b.CommonDetailsApplyConfiguration.Volumes, values[i])
	}
	return b
}

// WithVolumeMounts adds the given value to the VolumeMounts field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the VolumeMounts field.
func (b *DeploymentDetailsApplyConfiguration) WithVolumeMounts(values ...v1.VolumeMount) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.VolumeMounts = append(b.CommonDetailsApplyConfiguration.VolumeMounts, values[i])
	}
	return b
}

// WithServiceAccountName sets the ServiceAccountName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountName field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithServiceAccountName(value string) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.ServiceAccountName = &value
	return b
}

// WithResources sets the Resources field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Resources field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithResources(value v1.ResourceRequirements) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.Resources = &value
	return b
}

// WithSecurityContext sets the SecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecurityContext field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithSecurityContext(value v1.SecurityContext) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.SecurityContext = &value
	return b
}

// WithPodSecurityContext sets the PodSecurityContext field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodSecurityContext field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithPodSecurityContext(value v1.PodSecurityContext) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.PodSecurityContext = &value
	return b
}

// WithNodeName sets the NodeName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NodeName field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithNodeName(value string) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.NodeName = &value
	return b
}

// WithNodeSelector puts the entries into the NodeSelector field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the NodeSelector field,
// overwriting an existing map entries in NodeSelector field with the same key.
func (b *DeploymentDetailsApplyConfiguration) WithNodeSelector(entries map[string]string) *DeploymentDetailsApplyConfiguration {
	if b.CommonDetailsApplyConfiguration.NodeSelector == nil && len(entries) > 0 {
		b.CommonDetailsApplyConfiguration.NodeSelector = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.CommonDetailsApplyConfiguration.NodeSelector[k] = v
	}
	return b
}

// WithPriorityClassName sets the PriorityClassName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PriorityClassName field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithPriorityClassName(value string) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.PriorityClassName = &value
	return b
}

// WithAffinity sets the Affinity field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Affinity field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithAffinity(value v1.Affinity) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.Affinity = &value
	return b
}

// WithTolerations adds the given value to the Tolerations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Tolerations field.
func (b *DeploymentDetailsApplyConfiguration) WithTolerations(values ...v1.Toleration) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.Tolerations = append(b.CommonDetailsApplyConfiguration.Tolerations, values[i])
	}
	return b
}

// WithTopologySpreadConstraints adds the given value to the TopologySpreadConstraints field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the TopologySpreadConstraints field.
func (b *DeploymentDetailsApplyConfiguration) WithTopologySpreadConstraints(values ...v1.TopologySpreadConstraint) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.TopologySpreadConstraints = append(b.CommonDetailsApplyConfiguration.TopologySpreadConstraints, values[i])
	}
	return b
}

// WithInitContainers adds the given value to the InitContainers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the InitContainers field.
func (b *DeploymentDetailsApplyConfiguration) WithInitContainers(values ...v1.Container) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		b.CommonDetailsApplyConfiguration.InitContainers = append(b.CommonDetailsApplyConfiguration.InitContainers, values[i])
	}
	return b
}

// WithRestartPolicy sets the RestartPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RestartPolicy field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithRestartPolicy(value v1.RestartPolicy) *DeploymentDetailsApplyConfiguration {
	b.CommonDetailsApplyConfiguration.RestartPolicy = &value
	return b
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithType(value smesapcomv1alpha1.DeploymentType) *DeploymentDetailsApplyConfiguration {
	b.Type = &value
	return b
}

// WithReplicas sets the Replicas field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Replicas field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithReplicas(value int32) *DeploymentDetailsApplyConfiguration {
	b.Replicas = &value
	return b
}

// WithPorts adds the given value to the Ports field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Ports field.
func (b *DeploymentDetailsApplyConfiguration) WithPorts(values ...*PortsApplyConfiguration) *DeploymentDetailsApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithPorts")
		}
		b.Ports = append(b.Ports, *values[i])
	}
	return b
}

// WithLivenessProbe sets the LivenessProbe field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LivenessProbe field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithLivenessProbe(value v1.Probe) *DeploymentDetailsApplyConfiguration {
	b.LivenessProbe = &value
	return b
}

// WithReadinessProbe sets the ReadinessProbe field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ReadinessProbe field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithReadinessProbe(value v1.Probe) *DeploymentDetailsApplyConfiguration {
	b.ReadinessProbe = &value
	return b
}

// WithMonitoring sets the Monitoring field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Monitoring field is set to the value of the last call.
func (b *DeploymentDetailsApplyConfiguration) WithMonitoring(value *WorkloadMonitoringApplyConfiguration) *DeploymentDetailsApplyConfiguration {
	b.Monitoring = value
	return b
}
