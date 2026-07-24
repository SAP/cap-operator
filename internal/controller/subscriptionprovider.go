/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type serviceMetaInfo struct {
	Plan        string             `json:"plan"`
	Credentials serviceCredentials `json:"credentials"`
}

type serviceCredentials struct {
	XSAppName           string `json:"xsappname"`
	SaasRegistryEnabled bool   `json:"saasregistryenabled"`
	UAA                 *struct {
		XSAppName string `json:"xsappname"`
	} `json:"uaa"`
}

func (c *serviceCredentials) xsAppName() string {
	if c.XSAppName != "" {
		return c.XSAppName
	}
	if c.UAA != nil && c.UAA.XSAppName != "" {
		return c.UAA.XSAppName
	}
	return ""
}

func (c *Controller) resolveSubscriptionProvider(ctx context.Context, ca *v1alpha1.CAPApplication) (err error) {
	if ca.IsServicesOnly() {
		return nil
	}

	var (
		create, update bool
		subPro         *v1alpha1.SubscriptionProvider
	)
	subPro, err = c.crdInformerFactory.Sme().V1alpha1().SubscriptionProviders().Lister().SubscriptionProviders(ca.Namespace).Get(ca.Name)

	if k8sErrors.IsNotFound(err) {
		labels := map[string]string{
			LabelAppIdHash: sha1Sum(ca.Spec.ProviderSubaccountId, ca.Spec.BTPAppName),
		}
		subPro = &v1alpha1.SubscriptionProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ca.Name,
				Namespace: ca.Namespace,
				Labels:    labels,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(ca, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationKind)),
				},
			},
		}
		create = true
	} else if err != nil {
		return
	}

	if update, err = c.getUpdatedSubscriptionProvider(ctx, ca, subPro); err != nil {
		util.LogError(err, "Error managing SubscriptionProvider", string(Processing), ca, subPro)
		return
	}

	if create {
		util.LogInfo("Creating SubscriptionProvider", string(Processing), ca, subPro)
		_, err = c.crdClient.SmeV1alpha1().SubscriptionProviders(ca.Namespace).Create(ctx, subPro, metav1.CreateOptions{})
	} else if update {
		util.LogInfo("Updating SubscriptionProvider", string(Processing), ca, subPro)
		_, err = c.crdClient.SmeV1alpha1().SubscriptionProviders(ca.Namespace).Update(ctx, subPro, metav1.UpdateOptions{})
	}

	return
}

func (c *Controller) getUpdatedSubscriptionProvider(ctx context.Context, ca *v1alpha1.CAPApplication, subPro *v1alpha1.SubscriptionProvider) (modified bool, err error) {
	modified = false
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

	deps, err := c.buildSubscriptionDependencies(ca)
	if err != nil {
		return
	}

	spec := v1alpha1.SubscriptionProviderSpec{
		AppName:              ca.Spec.BTPAppName,
		ProviderSubaccountID: ca.Spec.ProviderSubaccountId,
		SubscriptionInfo:     subscriptionInfo,
		Dependencies:         deps,
	}

	// check whether changes have to be applied using hash comparison
	serializedSpec, err := json.Marshal(spec)
	if err != nil {
		return modified, fmt.Errorf("error serializing SubscriptionProvider spec: %s", err.Error())
	}
	hash := sha256Sum(string(serializedSpec))
	if subPro.Annotations[AnnotationResourceHash] != hash {
		subPro.Spec = *spec.DeepCopy()
		updateResourceAnnotation(&subPro.ObjectMeta, hash)
		modified = true
	}

	return modified, err
}

func (c *Controller) buildSubscriptionDependencies(ca *v1alpha1.CAPApplication) (string, error) {
	var dependenciesArray []map[string]string
	for _, service := range ca.Spec.BTP.Services {
		serviceCredInfo, err := util.ReadServiceCredentialsFromSecret[serviceMetaInfo](&service, ca.Namespace, c.kubeClient, true)
		if err != nil {
			util.LogError(err, "Failed to read secret for service", string(Processing), ca, nil, "service", service.Name, "secret", service.Secret)
			return "", err
		}

		dep := getSubscriptionProviderServiceDependency(service, serviceCredInfo)
		if dep != nil {
			dependenciesArray = append(dependenciesArray, dep)
		}
	}

	if len(dependenciesArray) == 0 {
		util.LogInfo("No subscription dependencies found", string(Processing), ca, nil)
		return "", nil
	}

	b, err := json.Marshal(dependenciesArray)
	if err != nil {
		return "", fmt.Errorf("failed to marshal subscription dependencies: %w", err)
	}

	util.LogInfo("Subscription dependencies resolved", string(Processing), ca, nil, "count", len(dependenciesArray), "dependencies", string(b))
	return string(b), nil
}

func getSubscriptionProviderServiceDependency(service v1alpha1.ServiceInfo, serviceCredInfo *serviceMetaInfo) map[string]string {
	if isSubscriptionServiceRelevantForDependencies(service, serviceCredInfo) {
		if name := serviceCredInfo.Credentials.xsAppName(); name != "" {
			if isSubscriptionSpecialDependency(service, serviceCredInfo) {
				return map[string]string{
					"appName": service.Class,
					"appId":   name,
				}
			} else {
				return map[string]string{
					"xsappname": name,
				}
			}
		}
	}
	return nil
}

func isSubscriptionServiceRelevantForDependencies(serviceInfo v1alpha1.ServiceInfo, creds *serviceMetaInfo) bool {
	if serviceInfo.GetSubscriptionDependency() == v1alpha1.SubscriptionDependencyAlways {
		return true
	}
	if serviceInfo.GetSubscriptionDependency() == v1alpha1.SubscriptionDependencyAuto {
		return isSubscriptionSpecialDependency(serviceInfo, creds) || creds.Credentials.SaasRegistryEnabled
	}
	return false
}

func isSubscriptionSpecialDependency(serviceInfo v1alpha1.ServiceInfo, creds *serviceMetaInfo) bool {
	return serviceInfo.Class == "destination" ||
		serviceInfo.Class == "connectivity" ||
		(serviceInfo.Class == "auditlog" && creds.Plan == "oauth2")
}
