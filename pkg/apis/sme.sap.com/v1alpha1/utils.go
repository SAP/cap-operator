/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	"os"
	"slices"
	"strconv"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	readyType                      = string(ConditionTypeReady)
	EnvMaxTenantVersionHistory     = "MAX_TENANT_VERSION_HISTORY"
	defaultMaxTenantVersionHistory = 10
	minTenantVersionHistory        = 3
)

func (ca *CAPApplication) SetStatusWithReadyCondition(state CAPApplicationState, readyStatus metav1.ConditionStatus, reason string, message string) {
	ca.Status.State = state
	ca.SetStatusCondition(readyType, readyStatus, reason, message)
}

func (ca *CAPApplication) SetStatusDomainSpecHash(hash string) {
	ca.Status.DomainSpecHash = hash
}

// SetStatusCondition updates/sets the conditions in the Status of the resource.
func (ca *CAPApplication) SetStatusCondition(conditionType string, readyStatus metav1.ConditionStatus, reason string, message string) {
	ca.Status.SetStatusCondition(metav1.Condition{Type: conditionType, Status: readyStatus, Reason: reason, Message: message, ObservedGeneration: ca.Generation})
}

func (cav *CAPApplicationVersion) SetStatusWithReadyCondition(state CAPApplicationVersionState, readyStatus metav1.ConditionStatus, reason string, message string) {
	cav.Status.State = state
	cav.Status.SetStatusCondition(metav1.Condition{Type: readyType, Status: readyStatus, Reason: reason, Message: message, ObservedGeneration: cav.Generation})
}

func (cav *CAPApplicationVersion) SetStatusFinishedJobs(finishedJob string) {
	if !cav.CheckFinishedJobs(finishedJob) {
		cav.Status.FinishedJobs = append(cav.Status.FinishedJobs, finishedJob)
	}
}

func (cav *CAPApplicationVersion) CheckFinishedJobs(finishedJob string) bool {
	return slices.Contains(cav.Status.FinishedJobs, finishedJob)
}

func (cat *CAPTenant) SetStatusWithReadyCondition(state CAPTenantState, readyStatus metav1.ConditionStatus, reason string, message string) {
	cat.Status.State = state
	cat.Status.SetStatusCondition(metav1.Condition{Type: readyType, Status: readyStatus, Reason: reason, Message: message, ObservedGeneration: cat.Generation})
}

func (cat *CAPTenant) SetStatusCAPApplicationVersion(cavName string) {
	if cat.Status.CurrentCAPApplicationVersionInstance != "" {
		if cat.Status.PreviousCAPApplicationVersions == nil {
			cat.Status.PreviousCAPApplicationVersions = []string{}
		}
		cat.Status.PreviousCAPApplicationVersions = append(cat.Status.PreviousCAPApplicationVersions, cat.Status.CurrentCAPApplicationVersionInstance)
		if len(cat.Status.PreviousCAPApplicationVersions) > minTenantVersionHistory { // clean up history only if it exceeds minimum
			max := defaultMaxTenantVersionHistory
			if sval, ok := os.LookupEnv(EnvMaxTenantVersionHistory); ok {
				if i, err := strconv.ParseInt(sval, 10, 0); err == nil {
					max = int(i)
				}
			}
			if len(cat.Status.PreviousCAPApplicationVersions) > max {
				cat.Status.PreviousCAPApplicationVersions = cat.Status.PreviousCAPApplicationVersions[1:] // remove one entry
			}
		}
	}
	cat.Status.CurrentCAPApplicationVersionInstance = cavName
}

func (ctop *CAPTenantOperation) SetStatusWithReadyCondition(state CAPTenantOperationState, readyStatus metav1.ConditionStatus, reason string, message string) {
	ctop.Status.State = state
	ctop.Status.SetStatusCondition(metav1.Condition{Type: readyType, Status: readyStatus, Reason: reason, Message: message, ObservedGeneration: ctop.Generation})
}

func (ctop *CAPTenantOperation) SetStatusCurrentStep(step *uint32, job *string) {
	ctop.Status.CurrentStep = step
	ctop.Status.ActiveJob = job
}

func (status *GenericStatus) SetStatusCondition(condition metav1.Condition) {
	status.ObservedGeneration = condition.ObservedGeneration
	meta.SetStatusCondition(&status.Conditions, condition)
}
