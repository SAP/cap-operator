/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"time"
)

type ReconcileResult struct {
	// the key in this map is a value which corresponds to a specific resource type
	requeueResources map[int][]RequeueItem
}

type RequeueItem struct {
	resourceKey NamespacedResourceKey
	// requeueAfter tells the Controller to re-queue the item after the specified duration. Defaults to 0s (immediate re-queue)
	requeueAfter time.Duration
}

func NewReconcileResult() *ReconcileResult {
	return &ReconcileResult{}
}

func NewReconcileResultWithResource(rid int, resourceName string, resourceNamespace string, requeueAfter time.Duration) *ReconcileResult {
	reconResult := NewReconcileResult()
	reconResult.AddResource(rid, resourceName, resourceNamespace, requeueAfter)
	return reconResult
}

func (r *ReconcileResult) AddResource(rid int, resourceName string, resourceNamespace string, after time.Duration) {
	resource := NamespacedResourceKey{Namespace: resourceNamespace, Name: resourceName}
	if r.requeueResources == nil {
		r.requeueResources = map[int][]RequeueItem{
			rid: {{resourceKey: resource, requeueAfter: after}},
		}
		return
	}
	items, ok := r.requeueResources[rid]
	if !ok {
		r.requeueResources[rid] = []RequeueItem{{resourceKey: resource, requeueAfter: after}}
	} else {
		r.requeueResources[rid] = append(items, RequeueItem{resourceKey: resource, requeueAfter: after})
	}
}
