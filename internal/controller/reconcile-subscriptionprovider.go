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

func (c *Controller) reconcileSubscriptionProvider(ctx context.Context, item QueueItem, _ int) (result *ReconcileResult, err error) {
	cached, err := c.crdInformerFactory.Sme().V1alpha1().SubscriptionProviders().Lister().SubscriptionProviders(item.ResourceKey.Namespace).Get(item.ResourceKey.Name)
	if err != nil {
		return nil, handleOperatorResourceErrors(err)
	}
	subPro := cached.DeepCopy()

	defer func() {
		if statusErr := c.updateSubscriptionProviderStatus(ctx, subPro); statusErr != nil && err == nil {
			err = statusErr
		}
	}()

	if subPro.Status.State != v1alpha1.SubscriptionProviderStateProcessing {
		subPro.SetStatusWithReadyCondition(v1alpha1.SubscriptionProviderStateProcessing, metav1.ConditionFalse, "Processing", "Processing subscription provider")
		result = NewReconcileResultWithResource(ResourceSubscriptionProvider, subPro.Name, subPro.Namespace, 0)
		return
	}

	// Fetch owning CAPApplication
	ownerRef, ok := getOwnerByKind(subPro.GetOwnerReferences(), v1alpha1.CAPApplicationKind)
	if !ok {
		err = fmt.Errorf("SubscriptionProvider %s.%s has no owning CAPApplication", subPro.Namespace, subPro.Name)
		subPro.SetStatusWithReadyCondition(v1alpha1.SubscriptionProviderStateError, metav1.ConditionFalse, "MissingOwner", err.Error())
		return
	}
	ca, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(subPro.Namespace).Get(ownerRef.Name)
	if err != nil {
		subPro.SetStatusWithReadyCondition(v1alpha1.SubscriptionProviderStateError, metav1.ConditionFalse, "OwnerNotFound", err.Error())
		return
	}

	dependencies, err := c.buildSubscriptionDependencies(ca)
	if err != nil {
		subPro.SetStatusWithReadyCondition(v1alpha1.SubscriptionProviderStateError, metav1.ConditionFalse, "DependencyResolutionFailed", err.Error())
		return
	}

	subPro.Status.Dependencies = dependencies
	subPro.SetStatusWithReadyCondition(v1alpha1.SubscriptionProviderStateReady, metav1.ConditionTrue, "Ready", "Subscription dependencies resolved")
	return
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

func (c *Controller) updateSubscriptionProviderStatus(ctx context.Context, subPro *v1alpha1.SubscriptionProvider) error {
	if isDeletionImminent(&subPro.ObjectMeta) {
		return nil
	}
	updated, err := c.crdClient.SmeV1alpha1().SubscriptionProviders(subPro.Namespace).UpdateStatus(ctx, subPro, metav1.UpdateOptions{})
	if updated != nil {
		*subPro = *updated
	}
	return err
}
