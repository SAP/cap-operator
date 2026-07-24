/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"
const AnnotationSubscriptionContextSecret = "sme.sap.com/subscription-context-secret"

// Returns an sha1 checksum for a given source string
func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}

// migrateAppIdLabels replaces the deprecated BTP app identifier label/annotation with
// the new app identifier label/annotation on the given ObjectMeta.
func migrateAppIdLabels(object *metav1.ObjectMeta, appIdHash, appId string) {
	if object.Labels == nil {
		object.Labels = map[string]string{}
	}
	if object.Annotations == nil {
		object.Annotations = map[string]string{}
	}
	object.Labels[controller.LabelAppIdHash] = appIdHash
	delete(object.Labels, LabelBTPApplicationIdentifierHash)
	object.Annotations[controller.AnnotationAppId] = appId
	delete(object.Annotations, "sme.sap.com/btp-app-identifier")
}

func ownerIdSelector(ownerNamespace, ownerName string) string {
	return labels.SelectorFromSet(map[string]string{
		controller.LabelOwnerIdentifierHash: sha1Sum(ownerNamespace, ownerName),
	}).String()
}

func migrateCAPApplicationVersions(crdClient versioned.Interface, namespace, caName, appIdHash, appId string) {
	cavs, err := crdClient.SmeV1alpha1().CAPApplicationVersions(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ownerIdSelector(namespace, caName),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPApplicationVersions", "capApplication", caName, "namespace", namespace)
		return
	}
	for _, cav := range cavs.Items {
		cavCopy := cav.DeepCopy()
		migrateAppIdLabels(&cavCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).Update(context.TODO(), cavCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPApplicationVersion", "name", cav.Name, "namespace", namespace)
		}
	}
}

func migrateCAPTenants(crdClient versioned.Interface, namespace, caName, appIdHash, appId string) {
	cats, err := crdClient.SmeV1alpha1().CAPTenants(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ownerIdSelector(namespace, caName),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenants", "capApplication", caName, "namespace", namespace)
		return
	}
	for _, cat := range cats.Items {
		catCopy := cat.DeepCopy()
		migrateAppIdLabels(&catCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPTenants(cat.Namespace).Update(context.TODO(), catCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPTenant", "name", cat.Name, "namespace", namespace)
		}
		migrateCAPTenantOperations(crdClient, cat.Namespace, cat.Name, appIdHash, appId)
	}
}

func migrateCAPTenantOperations(crdClient versioned.Interface, namespace, catName, appIdHash, appId string) {
	ctops, err := crdClient.SmeV1alpha1().CAPTenantOperations(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ownerIdSelector(namespace, catName),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenantOperations", "capTenant", catName, "namespace", namespace)
		return
	}
	for _, ctop := range ctops.Items {
		ctopCopy := ctop.DeepCopy()
		migrateAppIdLabels(&ctopCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPTenantOperations(ctop.Namespace).Update(context.TODO(), ctopCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPTenantOperation", "name", ctop.Name, "namespace", ctop.Namespace)
		}
	}
}

func needsMigration(ca *v1alpha1.CAPApplication, appIdHash string) bool {
	if ca.Labels[controller.LabelAppIdHash] != appIdHash {
		return true
	}
	if _, ok := ca.Labels[LabelBTPApplicationIdentifierHash]; ok {
		return true
	}
	return false
}

func migrateAppsAndSecrets(migrationDone chan bool, crdClient versioned.Interface, kubeClient kubernetes.Interface) {
	// Always set the channel to true in the end
	defer func() {
		migrationDone <- true
	}()

	// Go over all CAP applications and check if spec has ProviderSubaccountId set, if so trigger update after setting LabelAppIdHash and AnnotationAppId and remove LabelBTPApplicationIdentifierHash & AnnotationBTPApplicationIdentifier from all CAs.
	apps, err := crdClient.SmeV1alpha1().CAPApplications(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAP applications")
		return
	}

	for _, ca := range apps.Items {
		if missingProviderSubaccountID(crdClient, &ca) {
			continue
		}

		appIdHash := sha1Sum(ca.Spec.ProviderSubaccountId, ca.Spec.BTPAppName)
		appId := strings.Join([]string{ca.Spec.ProviderSubaccountId, ca.Spec.BTPAppName}, ".")

		// Update the CAPApplication itself if the new label is not yet set
		if needsMigration(&ca, appIdHash) {
			caCopy := ca.DeepCopy()
			migrateAppIdLabels(&caCopy.ObjectMeta, appIdHash, appId)
			if _, err := crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).Update(context.TODO(), caCopy, metav1.UpdateOptions{}); err != nil {
				klog.ErrorS(err, "Failed to update CAPApplication", "name", ca.Name, "namespace", ca.Namespace)
				continue
			}
		}

		migrateCAPApplicationVersions(crdClient, ca.Namespace, ca.Name, appIdHash, appId)
		migrateCAPTenants(crdClient, ca.Namespace, ca.Name, appIdHash, appId)

		// Create SubscriptionProvider and Subscription resources for any existing consumer tenants
		createSubscriptionResourcesForCA(crdClient, kubeClient, &ca)

		// Remove secrets that were preserved by the finalizer in the past.
		cleanupSecrets(ca.Namespace, kubeClient)
	}
	// annotate all tenants with subscription-guid based on the existing label, if not already set
	annotateAllTenants(crdClient)
}

func missingProviderSubaccountID(crdClient versioned.Interface, ca *v1alpha1.CAPApplication) bool {
	missing := ca.Spec.ProviderSubaccountId == ""

	if missing {
		ca.SetStatusWithReadyCondition(v1alpha1.CAPApplicationStateError, metav1.ConditionFalse, "MissingProviderSubaccountId", "set providerSubaccountId and restart CAP Operator controller to be able to use this app")
		_, err := crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).UpdateStatus(context.TODO(), ca, metav1.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update CAPApplication status", "name", ca.Name, "namespace", ca.Namespace)
		}
	}

	return missing
}

func cleanupSecrets(ns string, kubeClient kubernetes.Interface) {
	secrets, err := kubeClient.CoreV1().Secrets(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list secrets", "namespace", ns)
		return
	}
	for _, secret := range secrets.Items {
		// Remove finalizer from previously preserved Secret (if one exists) to allow it to be cleaned up if needed
		if removeFinalizer(&secret.Finalizers, controller.FinalizerCAPApplication) {
			if _, err = kubeClient.CoreV1().Secrets(ns).Update(context.TODO(), &secret, metav1.UpdateOptions{}); err != nil {
				klog.ErrorS(err, "Failed to update secret", "name", secret.Name, "namespace", ns)
				continue
			}
			klog.InfoS("Removed finalizer from secret", "name", secret.Name, "namespace", ns)
		}
	}
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

func annotateAllTenants(crdClient versioned.Interface) {
	count := 0
	// Get all CAPTenants and check if they have the new subscription-guid annotation set, if not set it based on the existing label
	tenants, err := crdClient.SmeV1alpha1().CAPTenants(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenants")
		return
	}
	for _, tenant := range tenants.Items {
		subscriptionGUID, ok := tenant.Labels[controller.MetadataSubscriptionGUID]
		if !ok || subscriptionGUID == "" {
			klog.InfoS("CAPTenant is missing subscription-guid label", "name", tenant.Name, "namespace", tenant.Namespace)
			continue
		}
		if tenant.Annotations[controller.MetadataSubscriptionGUID] != subscriptionGUID {
			tenant.Annotations[controller.MetadataSubscriptionGUID] = subscriptionGUID
			if _, err := crdClient.SmeV1alpha1().CAPTenants(tenant.Namespace).Update(context.TODO(), &tenant, metav1.UpdateOptions{}); err != nil {
				klog.ErrorS(err, "Failed to update CAPTenant annotation", "name", tenant.Name, "namespace", tenant.Namespace)
				continue
			}
			count++
		}
	}
	klog.InfoS("Annotated CAPTenants with subscription-guid", "count", count)
}

// createSubscriptionResourcesForCA creates a SubscriptionProvider for the given CAPApplication (if not present)
// and a Subscription for each existing consumer CAPTenant that has a subscription context secret.
// Skipped when the CA has no providerSubaccountId set, or when it is a services-only scenario.
func createSubscriptionResourcesForCA(crdClient versioned.Interface, kubeClient kubernetes.Interface, ca *v1alpha1.CAPApplication) {
	if ca.Spec.ProviderSubaccountId == "" || ca.IsServicesOnly() {
		return
	}
	createSubscriptionProviderIfNeeded(crdClient, ca)
	createSubscriptionsForTenants(crdClient, kubeClient, ca)
}

func createSubscriptionProviderIfNeeded(crdClient versioned.Interface, ca *v1alpha1.CAPApplication) {
	_, err := crdClient.SmeV1alpha1().SubscriptionProviders(ca.Namespace).Get(context.TODO(), ca.Name, metav1.GetOptions{})
	if err == nil {
		return
	}
	if !k8sErrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to check SubscriptionProvider existence", "name", ca.Name, "namespace", ca.Namespace)
		return
	}

	var subscriptionInfo v1alpha1.SubscriptionInfo
	for _, svc := range ca.Spec.BTP.Services {
		switch svc.Class {
		case "subscription-manager":
			subscriptionInfo.Type = "subscription-manager"
			subscriptionInfo.SubscriptionSecret = svc.Secret
		case "saas-registry":
			subscriptionInfo.Type = "saas-registry"
			subscriptionInfo.SubscriptionSecret = svc.Secret
			if xsuaaInfo := util.GetXSUAAInfo(ca.Spec.BTP.Services, ca); xsuaaInfo != nil {
				subscriptionInfo.AuthSecret = xsuaaInfo.Secret
			}
		}
		if subscriptionInfo.SubscriptionSecret != "" {
			break
		}
	}

	appIdHash := sha1Sum(ca.Spec.ProviderSubaccountId, ca.Spec.BTPAppName)
	_, err = crdClient.SmeV1alpha1().SubscriptionProviders(ca.Namespace).Create(context.TODO(), &v1alpha1.SubscriptionProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ca.Name,
			Namespace: ca.Namespace,
			Labels:    map[string]string{controller.LabelAppIdHash: appIdHash},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind)),
			},
		},
		Spec: v1alpha1.SubscriptionProviderSpec{
			AppName:              ca.Spec.BTPAppName,
			ProviderSubaccountID: ca.Spec.ProviderSubaccountId,
			SubscriptionInfo:     subscriptionInfo,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to create SubscriptionProvider", "name", ca.Name, "namespace", ca.Namespace)
		return
	}
	klog.InfoS("Created SubscriptionProvider", "name", ca.Name, "namespace", ca.Namespace)
}

func createSubscriptionsForTenants(crdClient versioned.Interface, kubeClient kubernetes.Interface, ca *v1alpha1.CAPApplication) {
	cats, err := crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ownerIdSelector(ca.Namespace, ca.Name),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenants for subscription migration", "capApplication", ca.Name, "namespace", ca.Namespace)
		return
	}

	appIdHash := sha1Sum(ca.Spec.ProviderSubaccountId, ca.Spec.BTPAppName)

	for _, cat := range cats.Items {
		// Skip provider tenants: require both subscription-guid label and annotation to be present
		guid := cat.Labels[controller.MetadataSubscriptionGUID]
		if guid == "" || cat.Annotations[controller.MetadataSubscriptionGUID] == "" {
			continue
		}

		// Skip tenants without a subscription context secret (no payload to migrate)
		secretName := cat.Annotations[AnnotationSubscriptionContextSecret]
		if secretName == "" {
			klog.InfoS("Skipping tenant without subscription context secret annotation", "tenant", cat.Name, "namespace", cat.Namespace)
			continue
		}

		// Skip if a Subscription for this tenant already exists
		existingSubs, err := crdClient.SmeV1alpha1().Subscriptions(ca.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{
				controller.LabelAppIdHash: appIdHash,
				controller.LabelTenantId:  cat.Spec.TenantId,
			}).String(),
		})
		if err != nil {
			klog.ErrorS(err, "Failed to check existing Subscriptions", "tenant", cat.Name, "namespace", cat.Namespace)
			continue
		}
		if len(existingSubs.Items) > 0 {
			continue
		}

		// Read the subscription context secret to get the original request payload
		secret, err := kubeClient.CoreV1().Secrets(ca.Namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to read subscription context secret", "secret", secretName, "tenant", cat.Name, "namespace", cat.Namespace)
			continue
		}

		if cat.Labels[controller.LabelTenantType] != controller.TenantTypeProvider {
			sub, err := crdClient.SmeV1alpha1().Subscriptions(ca.Namespace).Create(context.TODO(), &v1alpha1.Subscription{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: ca.Name + "-",
					Namespace:    ca.Namespace,
					Labels: map[string]string{
						controller.LabelAppIdHash:           appIdHash,
						controller.LabelTenantId:            cat.Spec.TenantId,
						controller.MetadataSubscriptionGUID: guid,
					},
				},
				Spec: v1alpha1.SubscriptionSpec{
					AppName:                    ca.Spec.BTPAppName,
					ProviderSubaccountId:       ca.Spec.ProviderSubaccountId,
					TenantId:                   cat.Spec.TenantId,
					Subdomain:                  cat.Spec.SubDomain,
					SubscriptionGuid:           guid,
					SubscriptionRequestPayload: string(secret.Data["subscriptionContext"]),
				},
			}, metav1.CreateOptions{})
			if err != nil {
				klog.ErrorS(err, "Failed to create Subscription", "tenant", cat.Name, "namespace", cat.Namespace)
				continue
			}
			cat.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(sub, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.SubscriptionKind)), *metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind))}
		} else {
			cat.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind))}
		}
		// Get rid of the old annotation
		delete(cat.Annotations, AnnotationSubscriptionContextSecret)

		// Update the CAPTenant resource to remove the annotation
		crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).Update(context.TODO(), &cat, metav1.UpdateOptions{})
		// Finally get rid of the old secrets that have now been migrated to
		kubeClient.CoreV1().Secrets(ca.Namespace).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})

		klog.InfoS("Created Subscription for tenant", "tenant", cat.Name, "namespace", cat.Namespace, "guid", guid)
	}
}
