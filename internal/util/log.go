/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"reflect"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

const (
	Step          = "step"
	Name          = "name"
	Namespace     = "namespace"
	Kind          = "kind"
	DependentName = "dependentName"
	DependentKind = "dependentKind"
)

const LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"

func GetLogger() logr.Logger {
	logger, _ := zap.NewProduction()
	return zapr.NewLogger(logger)
}

func extractEntityMeta(entity interface{}, isRoot bool, skipLabel bool) map[string]string {
	obj, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(entity)
	objectMeta := &unstructured.Unstructured{Object: obj}
	// Try to get the kind from the object meta
	kind := objectMeta.GetKind()
	// If kind is empty, try to get it from the original entity using reflection
	if kind == "" {
		typ := reflect.TypeOf(entity)
		if typ.Kind() == reflect.Ptr {
			// Get the underlying element type
			kind = typ.Elem().Name()
		} else {
			// Get the type name
			kind = typ.Name()
		}
	}

	var args map[string]string

	if isRoot {
		args = map[string]string{
			Name:      objectMeta.GetName(),
			Namespace: objectMeta.GetNamespace(),
			Kind:      kind,
		}
		if !skipLabel {
			args[LabelBTPApplicationIdentifierHash] = objectMeta.GetLabels()[LabelBTPApplicationIdentifierHash]
		}
	} else {
		args = map[string]string{
			DependentName: objectMeta.GetName(),
			DependentKind: kind,
		}
	}

	return args
}

func extractArgs(entityMeta map[string]string) []interface{} {
	args := []interface{}{}
	for key, val := range entityMeta {
		args = append(args, key, val)
	}
	return args
}

func logArgs(step string, entity interface{}, child interface{}, inArgs ...interface{}) []interface{} {
	args := []interface{}{}
	skipLabel := false
	args = append(args, Step, step)

	// Some Root entities don't have LabelBTPApplicationIdentifierHash but this is set via the args instead!
	for _, arg := range inArgs {
		if arg == LabelBTPApplicationIdentifierHash {
			skipLabel = true
			break
		}
	}

	rootMeta := extractEntityMeta(entity, true, skipLabel)
	args = append(args, extractArgs(rootMeta)...)
	// Child entity
	skipLabel = true
	if child != nil {
		childMeta := extractEntityMeta(child, false, skipLabel)
		args = append(args, extractArgs(childMeta)...)
	}
	args = append(args, inArgs...)
	return args
}

func LogInfo(msg string, step string, entity interface{}, child interface{}, args ...interface{}) {
	overallArgs := logArgs(step, entity, child, args...)
	klog.InfoS(msg, overallArgs...)
}

func LogError(error error, msg string, step string, entity interface{}, child interface{}, args ...interface{}) {
	overallArgs := logArgs(step, entity, child, args...)
	klog.ErrorS(error, msg, overallArgs...)
}

func LogWarning(args ...interface{}) {
	klog.Warning(args...)
}
