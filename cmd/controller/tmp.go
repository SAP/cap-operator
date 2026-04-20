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
	"time"

	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	"google.golang.org/protobuf/types/known/durationpb"
	networkingv1 "istio.io/api/networking/v1"
	"istio.io/api/networking/v1alpha3"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	istio "istio.io/client-go/pkg/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/klog/v2"
)

func checkDRs(checkDone chan bool, istioClient istio.Interface, crdClient versioned.Interface) {
	// Always set the channel to true in the end
	defer func() {
		checkDone <- true
	}()

	// Create new DestinationRule for Router workload of each CAPApplicationVersion
	appVersions, err := crdClient.SmeV1alpha1().CAPApplicationVersions(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list application versions")
		return
	}
	for _, cav := range appVersions.Items {
		drName := getDRName(cav)
		// Ignore application versions without router workload
		if drName != "" {
			_, err := istioClient.NetworkingV1().DestinationRules(cav.Namespace).Get(context.TODO(), drName, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				err = nil
				dr := &istionwv1.DestinationRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:            drName,
						Namespace:       cav.Namespace,
						Labels:          map[string]string{},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind))},
					},
					Spec: networkingv1.DestinationRule{
						Host: drName + "-svc" + "." + cav.Namespace + ".svc.cluster.local",
						TrafficPolicy: &networkingv1.TrafficPolicy{
							LoadBalancer: &networkingv1.LoadBalancerSettings{
								LbPolicy: &networkingv1.LoadBalancerSettings_ConsistentHash{
									ConsistentHash: &networkingv1.LoadBalancerSettings_ConsistentHashLB{
										HashKey: &v1alpha3.LoadBalancerSettings_ConsistentHashLB_HttpCookie{
											HttpCookie: &networkingv1.LoadBalancerSettings_ConsistentHashLB_HTTPCookie{
												Name: "CAPOP_ROUTER_STICKY",
												Path: "/",
												Ttl:  durationpb.New(0 * time.Second),
											},
										},
									},
								},
							},
						},
					},
				}
				_, err = istioClient.NetworkingV1().DestinationRules(cav.Namespace).Create(context.TODO(), dr, metav1.CreateOptions{})
			}
			if err != nil {
				klog.ErrorS(err, "Error managing DestinationRule: ", drName)
				continue
			}
		}
	}

	// Get all tenants
	tenants, err := crdClient.SmeV1alpha1().CAPTenants(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list tenants")
		return
	}
	// Delete all DestinationRules in the tenant's namespace that have the relevant ownerId label
	for _, tenant := range tenants.Items {
		ownerIdentifierHash := sha1Sum(tenant.Namespace, tenant.Name)
		ownerLabelHashReq, _ := labels.NewRequirement(controller.LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
		ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)
		err := istioClient.NetworkingV1().DestinationRules(tenant.Namespace).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{
			LabelSelector: ownerLabelHashReqSelector.String(),
		})
		if err != nil {
			klog.ErrorS(err, "Failed to delete DestinationRules for tenant: ", tenant.Name)
		}
	}
}

func getDRName(cav v1alpha1.CAPApplicationVersion) string {
	drName := ""
	for _, workload := range cav.Spec.Workloads {
		if workload.DeploymentDefinition != nil && workload.DeploymentDefinition.Type == v1alpha1.DeploymentRouter {
			drName = fmt.Sprintf("%s-%s", cav.Name, strings.ToLower(workload.Name))
			break
		}
	}
	return drName
}

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
	delete(object.Labels, controller.LabelBTPApplicationIdentifierHash)
	object.Annotations[controller.AnnotationAppId] = appId
	delete(object.Annotations, controller.AnnotationBTPApplicationIdentifier)
}

func btpAppIdHashSelector(ca v1alpha1.CAPApplication) string {
	return labels.SelectorFromSet(map[string]string{
		controller.LabelBTPApplicationIdentifierHash: sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName),
	}).String()
}

func migrateCAPApplicationVersions(crdClient versioned.Interface, ca v1alpha1.CAPApplication, appIdHash, appId string) {
	cavs, err := crdClient.SmeV1alpha1().CAPApplicationVersions(ca.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: btpAppIdHashSelector(ca),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPApplicationVersions", "capApplication", ca.Name, "namespace", ca.Namespace)
		return
	}
	for _, cav := range cavs.Items {
		cavCopy := cav.DeepCopy()
		migrateAppIdLabels(&cavCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPApplicationVersions(cav.Namespace).Update(context.TODO(), cavCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPApplicationVersion", "name", cav.Name, "namespace", cav.Namespace)
		}
	}
}

func migrateCAPTenants(crdClient versioned.Interface, ca v1alpha1.CAPApplication, appIdHash, appId string) {
	cats, err := crdClient.SmeV1alpha1().CAPTenants(ca.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: btpAppIdHashSelector(ca),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenants", "capApplication", ca.Name, "namespace", ca.Namespace)
		return
	}
	for _, cat := range cats.Items {
		catCopy := cat.DeepCopy()
		migrateAppIdLabels(&catCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPTenants(cat.Namespace).Update(context.TODO(), catCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPTenant", "name", cat.Name, "namespace", cat.Namespace)
		}
	}
}

func migrateCAPTenantOperations(crdClient versioned.Interface, ca v1alpha1.CAPApplication, appIdHash, appId string) {
	ctops, err := crdClient.SmeV1alpha1().CAPTenantOperations(ca.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: btpAppIdHashSelector(ca),
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list CAPTenants", "capApplication", ca.Name, "namespace", ca.Namespace)
		return
	}
	for _, ctop := range ctops.Items {
		ctopCopy := ctop.DeepCopy()
		migrateAppIdLabels(&ctopCopy.ObjectMeta, appIdHash, appId)
		if _, err := crdClient.SmeV1alpha1().CAPTenantOperations(ctop.Namespace).Update(context.TODO(), ctopCopy, metav1.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update CAPTenant", "name", ctop.Name, "namespace", ctop.Namespace)
		}
	}
}

func needsMigration(ca *v1alpha1.CAPApplication, appIdHash string) bool {
	if ca.Labels[controller.LabelAppIdHash] != appIdHash {
		return true
	}
	if _, ok := ca.Labels[controller.LabelBTPApplicationIdentifierHash]; ok {
		return true
	}
	return false
}

func migrateApps(migrationDone chan bool, crdClient versioned.Interface) {
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
		if ca.Spec.ProviderSubaccountId == "" {
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

		migrateCAPApplicationVersions(crdClient, ca, appIdHash, appId)
		migrateCAPTenants(crdClient, ca, appIdHash, appId)
		migrateCAPTenantOperations(crdClient, ca, appIdHash, appId)
	}
}
