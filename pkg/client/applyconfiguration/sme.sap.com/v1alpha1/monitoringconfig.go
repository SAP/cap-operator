/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
)

// MonitoringConfigApplyConfiguration represents a declarative configuration of the MonitoringConfig type for use
// with apply.
type MonitoringConfigApplyConfiguration struct {
	ScrapeInterval *v1alpha1.Duration `json:"interval,omitempty"`
	WorkloadPort   *string            `json:"port,omitempty"`
	Path           *string            `json:"path,omitempty"`
	Timeout        *v1alpha1.Duration `json:"scrapeTimeout,omitempty"`
}

// MonitoringConfigApplyConfiguration constructs a declarative configuration of the MonitoringConfig type for use with
// apply.
func MonitoringConfig() *MonitoringConfigApplyConfiguration {
	return &MonitoringConfigApplyConfiguration{}
}

// WithScrapeInterval sets the ScrapeInterval field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ScrapeInterval field is set to the value of the last call.
func (b *MonitoringConfigApplyConfiguration) WithScrapeInterval(value v1alpha1.Duration) *MonitoringConfigApplyConfiguration {
	b.ScrapeInterval = &value
	return b
}

// WithWorkloadPort sets the WorkloadPort field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the WorkloadPort field is set to the value of the last call.
func (b *MonitoringConfigApplyConfiguration) WithWorkloadPort(value string) *MonitoringConfigApplyConfiguration {
	b.WorkloadPort = &value
	return b
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *MonitoringConfigApplyConfiguration) WithPath(value string) *MonitoringConfigApplyConfiguration {
	b.Path = &value
	return b
}

// WithTimeout sets the Timeout field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Timeout field is set to the value of the last call.
func (b *MonitoringConfigApplyConfiguration) WithTimeout(value v1alpha1.Duration) *MonitoringConfigApplyConfiguration {
	b.Timeout = &value
	return b
}