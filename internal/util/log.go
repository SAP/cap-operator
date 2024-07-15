package util

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

const (
	Step          = "step"
	Name          = "name"
	Namespace     = "namespace"
	Kind          = "kind"
	DependantName = "dependantName"
	DependantKind = "dependantKind"
)

const LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"

func GetLogger() logr.Logger {
	logger, _ := zap.NewProduction()
	return zapr.NewLogger(logger)
}

func extractEntityMeta(entity interface{}, isRoot bool, skipLabel bool) map[string]string {
	runtimeObj := entity.(runtime.Object) // Convert to runtime object to determine Kind in a generic way
	kind := runtimeObj.GetObjectKind()
	objectMeta, _ := meta.Accessor(entity)
	var args map[string]string

	if isRoot {
		args = map[string]string{
			Name:      objectMeta.GetName(),
			Namespace: objectMeta.GetNamespace(),
			Kind:      kind.GroupVersionKind().Kind,
		}
		if !skipLabel {
			args[LabelBTPApplicationIdentifierHash] = objectMeta.GetLabels()[LabelBTPApplicationIdentifierHash]
		}
	} else {
		args = map[string]string{
			DependantName: objectMeta.GetName(),
			DependantKind: kind.GroupVersionKind().Kind,
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
	skipLabel := true
	args = append(args, Step, step)
	for _, arg := range inArgs {
		if arg == LabelBTPApplicationIdentifierHash {
			skipLabel = false
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
