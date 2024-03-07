/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

const recoveredPanic = "RecoveredPanic"

const (
	certManagerGardener      = "gardener"
	certManagerCertManagerIO = "cert-manager.io"
	dnsManagerGardener       = "gardener"
	dnsManagerKubernetes     = "kubernetes"
)

const (
	certManagerEnv = "CERT_MANAGER"
	dnsManagerEnv  = "DNS_MANAGER"
	dnsTargetEnv   = "DNS_TARGET"
)

type ownerInfo struct {
	ownerNamespace  string
	ownerName       string
	ownerGeneration int64
}
type appMetadataIdentifiers struct {
	globalAccountId string
	appName         string
	ownerInfo       *ownerInfo
}

func getOwnerByKind(owners []metav1.OwnerReference, kind string) (*metav1.OwnerReference, bool) {
	for _, o := range owners {
		if o.APIVersion == v1alpha1.SchemeGroupVersion.String() && o.Kind == kind && *o.Controller {
			return &o, true
		}
	}
	return nil, false
}

func getOwnerFromObjectMetadata(objectMeta metav1.Object, dependentKind string) (NamespacedResourceKey, bool) {
	var ownerKey NamespacedResourceKey

	annotations := objectMeta.GetAnnotations()

	if annotations[AnnotationOwnerIdentifier] != "" {
		identifier := strings.Split(annotations[AnnotationOwnerIdentifier], ".")
		if len(identifier) == 3 && identifier[0] == dependentKind {
			ownerKey.Namespace = identifier[1]
			ownerKey.Name = identifier[2]
			return ownerKey, true
		}
	}

	return ownerKey, false
}

func convertToLocalObjectReferences(entries []string) []corev1.LocalObjectReference {
	localObjects := make([]corev1.LocalObjectReference, 0)
	for _, entry := range entries {
		localObjects = append(localObjects, corev1.LocalObjectReference{Name: entry})
	}
	return localObjects
}

func getResourceKindFromKey(key int) string {
	kind, ok := KindMap[key]
	if !ok {
		kind = "unknown"
	}
	return kind
}

/*
check whether the status of a custom resource (sme.sap.com) is Ready (based on metav1.Condition)
*/
func isCROConditionReady(status v1alpha1.GenericStatus) bool {
	if status.Conditions == nil {
		return false
	}

	return slices.ContainsFunc(status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == string(v1alpha1.ConditionTypeReady) && condition.Status == metav1.ConditionTrue
	})
}

func addFinalizer(finalizers *[]string, finalizerType string) bool {
	finalizerExists := slices.ContainsFunc(*finalizers, func(f string) bool {
		return f == finalizerType
	})

	if !finalizerExists {
		*finalizers = append(*finalizers, finalizerType)
		return true
	}
	return false
}

func removeFinalizer(finalizers *[]string, finalizerType string) bool {
	finalizerExists := false
	adjusted := make([]string, 0)
	for _, f := range *finalizers {
		if f != finalizerType {
			adjusted = append(adjusted, f)
		} else {
			finalizerExists = true
		}
	}

	if finalizerExists {
		*finalizers = adjusted
		return true
	}
	return false
}

func certificateManager() string {
	mgr := certManagerGardener
	env := os.Getenv(certManagerEnv)
	if env != "" {
		if env == certManagerGardener || env == certManagerCertManagerIO {
			mgr = env
		} else {
			klog.Error("Error parsing certificate manager environment variable: invalid value")
		}
	}
	return mgr
}

func dnsManager() string {
	mgr := dnsManagerGardener
	env := os.Getenv(dnsManagerEnv)
	if env != "" {
		if env == dnsManagerGardener || env == dnsManagerKubernetes {
			mgr = env
		} else {
			klog.Error("Error parsing DNS manager environment variable: invalid value")
		}
	}
	return mgr
}

func envDNSTarget() string {
	target := ""
	env := os.Getenv(dnsTargetEnv)
	if env != "" {
		// convert to lower case
		target = strings.ToLower(env)
	}
	return target
}

func updateResourceAnnotation(object *metav1.ObjectMeta, hash string) {
	if object.Annotations == nil {
		object.Annotations = map[string]string{}
	}
	// Update Annotation hash
	object.Annotations[AnnotationResourceHash] = hash
}

// Returns an sha256 checksum for a given source string
func sha256Sum(source ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}

// Returns an sha1 checksum for a given source string
func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}

func amendObjectMetadata(object *metav1.ObjectMeta, annotatedOldLabel string, hashLabel string, oldValue string, hashedValue string) (updated bool) {
	// Check if old label exists, if so remove it
	if _, ok := object.Labels[annotatedOldLabel]; ok {
		// Should never happen
		klog.Infof("Unexpected label %s=%s found for resource %s.%s", annotatedOldLabel, oldValue, object.Namespace, object.Name)
		delete(object.Labels, annotatedOldLabel)
		updated = true
	}
	// Add hashed label as the new label with the hashed identifier value
	if _, ok := object.Labels[hashLabel]; !ok {
		object.Labels[hashLabel] = hashedValue
		updated = true
	}
	// Add old label as an annotation with the old value
	if _, ok := object.Annotations[annotatedOldLabel]; !ok {
		object.Annotations[annotatedOldLabel] = oldValue
		updated = true
	}
	// return if something was updated
	return updated
}

func updateLabelAnnotationMetadata(object *metav1.ObjectMeta, appMetadata *appMetadataIdentifiers) (updated bool) {
	if object.Labels == nil {
		object.Labels = make(map[string]string)
	}
	if object.Annotations == nil {
		object.Annotations = map[string]string{}
	}

	// Update BTP Application Identifier
	if appMetadata.globalAccountId != "" && amendObjectMetadata(object, AnnotationBTPApplicationIdentifier, LabelBTPApplicationIdentifierHash, strings.Join([]string{appMetadata.globalAccountId, appMetadata.appName}, "."), sha1Sum(appMetadata.globalAccountId, appMetadata.appName)) {
		updated = true
	}

	// Update OwnerInfo if owner details exists
	if appMetadata.ownerInfo != nil {
		if amendObjectMetadata(object, AnnotationOwnerIdentifier, LabelOwnerIdentifierHash, strings.Join([]string{appMetadata.ownerInfo.ownerNamespace, appMetadata.ownerInfo.ownerName}, "."), sha1Sum(appMetadata.ownerInfo.ownerNamespace, appMetadata.ownerInfo.ownerName)) {
			updated = true
		}
		if _, ok := object.Labels[LabelOwnerGeneration]; !ok {
			object.Labels[LabelOwnerGeneration] = strconv.FormatInt(appMetadata.ownerInfo.ownerGeneration, 10)
		}
	}

	return updated
}

func (c *Controller) setCAStatusError(ctx context.Context, itemKey NamespacedResourceKey, err error) {
	cached, _ := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(itemKey.Namespace).Get(itemKey.Name)
	ca := cached.DeepCopy()
	ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, recoveredPanic, err.Error())
	c.crdClient.SmeV1alpha1().CAPApplications(itemKey.Namespace).UpdateStatus(ctx, ca, metav1.UpdateOptions{})
}

func (c *Controller) setCAVStatusError(ctx context.Context, itemKey NamespacedResourceKey, err error) {
	cached, _ := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(itemKey.Namespace).Get(itemKey.Name)
	cav := cached.DeepCopy()
	cav.SetStatusWithReadyCondition(v1alpha1.CAPApplicationVersionStateError, metav1.ConditionFalse, recoveredPanic, err.Error())
	c.crdClient.SmeV1alpha1().CAPApplicationVersions(itemKey.Namespace).UpdateStatus(ctx, cav, metav1.UpdateOptions{})
}

func (c *Controller) setCATStatusError(ctx context.Context, itemKey NamespacedResourceKey, err error) {
	cached, _ := c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Lister().CAPTenants(itemKey.Namespace).Get(itemKey.Name)
	cat := cached.DeepCopy()
	var state v1alpha1.CAPTenantState
	// Determine error state based on current tenant state
	if cat.Status.State == v1alpha1.CAPTenantStateUpgrading {
		state = v1alpha1.CAPTenantStateUpgradeError
	} else {
		state = v1alpha1.CAPTenantStateProvisioningError
	}
	cat.SetStatusWithReadyCondition(state, metav1.ConditionFalse, recoveredPanic, err.Error())
	c.crdClient.SmeV1alpha1().CAPTenants(itemKey.Namespace).UpdateStatus(ctx, cat, metav1.UpdateOptions{})
}

func (c *Controller) setCTOPStatusError(ctx context.Context, itemKey NamespacedResourceKey, err error) {
	cached, _ := c.crdInformerFactory.Sme().V1alpha1().CAPTenantOperations().Lister().CAPTenantOperations(itemKey.Namespace).Get(itemKey.Name)
	ctop := cached.DeepCopy()
	ctop.SetStatusWithReadyCondition(v1alpha1.CAPTenantOperationStateFailed, metav1.ConditionFalse, recoveredPanic, err.Error())
	c.crdClient.SmeV1alpha1().CAPTenantOperations(itemKey.Namespace).UpdateStatus(ctx, ctop, metav1.UpdateOptions{})
}
