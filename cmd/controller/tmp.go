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

const (
	LabelOwnerIdentifierHash = "sme.sap.com/owner-identifier-hash"
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
		ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
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
