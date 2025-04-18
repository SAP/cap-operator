/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// DeletionRulesApplyConfiguration represents a declarative configuration of the DeletionRules type for use
// with apply.
type DeletionRulesApplyConfiguration struct {
	Metrics          []MetricRuleApplyConfiguration `json:"metrics,omitempty"`
	ScalarExpression *string                        `json:"expression,omitempty"`
}

// DeletionRulesApplyConfiguration constructs a declarative configuration of the DeletionRules type for use with
// apply.
func DeletionRules() *DeletionRulesApplyConfiguration {
	return &DeletionRulesApplyConfiguration{}
}

// WithMetrics adds the given value to the Metrics field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Metrics field.
func (b *DeletionRulesApplyConfiguration) WithMetrics(values ...*MetricRuleApplyConfiguration) *DeletionRulesApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithMetrics")
		}
		b.Metrics = append(b.Metrics, *values[i])
	}
	return b
}

// WithScalarExpression sets the ScalarExpression field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ScalarExpression field is set to the value of the last call.
func (b *DeletionRulesApplyConfiguration) WithScalarExpression(value string) *DeletionRulesApplyConfiguration {
	b.ScalarExpression = &value
	return b
}
