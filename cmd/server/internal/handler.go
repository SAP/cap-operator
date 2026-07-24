/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
)

const (
	AnnotationSaaSAdditionalOutput = "sme.sap.com/saas-additional-output"
)

const (
	LabelAppIdHash           = "sme.sap.com/app-identifier-hash"
	LabelTenantId            = "sme.sap.com/btp-tenant-id"
	MetadataSubscriptionGUID = "sme.sap.com/subscription-guid"
)

const (
	ResourceCreated      = "resource created successfully"
	ResourceUpdated      = "resource updated successfully"
	ResourceFound        = "resource exists"
	ResourceDeleted      = "resource deleted successfully"
	ResourceNotFound     = "resource not found"
	SubscriptionNotFound = "subscription not found"
	SubscriptionFound    = "Subscription found"
)

const ErrorOccurred = "Error occurred "
const InvalidRequestMethod = "invalid request method"
const AuthorizationCheckFailed = "authorization check failed"
const BearerPrefix = "Bearer "
const BasicPrefix = "Basic "
const ContentType = "Content-Type"

const (
	CallbackSucceeded              = "SUCCEEDED"
	CallbackFailed                 = "FAILED"
	ProvisioningSucceededMessage   = "Provisioning successful"
	ProvisioningFailedMessage      = "Provisioning failed"
	DeprovisioningSucceededMessage = "Deprovisioning successful"
	DeprovisioningFailedMessage    = "Deprovisioning failed"
)

const (
	Step                 = "step"
	TenantProvisioning   = "Tenant Provisioning"
	TenantDeprovisioning = "Tenant Deprovisioning"
	GetDependencies      = "Get Dependencies"
)

type RequestInfo struct {
	// One of "SMS" or "SaaS"
	subscriptionType subscriptionType
	// subscription domain from the subscription request, used for constructing the subscription URL. If not present, existing fallbacks will be used
	subscriptionDomain string
	// payload Details
	payload *payloadDetails
	// header details
	headerDetails *requestHeaderDetails
}

type subscriptionType string

const (
	SaaS subscriptionType = "SaaS"
	SMS  subscriptionType = "SMS"
)

type payloadDetails struct {
	subscriptionGUID     string
	tenantId             string
	subdomain            string
	globalAccountId      string
	providerSubaccountId string
	appName              string
	raw                  *map[string]any
}

type requestHeaderDetails struct {
	authorization        string
	callbackInfo         string
	xForwardedClientCert string
}

type Result struct {
	Subscription *v1alpha1.Subscription
	Message      string
}

type SubscriptionHandler struct {
	Clientset           versioned.Interface
	KubeClientset       kubernetes.Interface
	httpClientGenerator httpClientGenerator
}

type callbackResponse struct {
	Status           string          `json:"status"`
	Message          string          `json:"message"`
	AdditionalOutput *map[string]any `json:"additionalOutput,omitempty"`
}

type SaaSCallbackResponse struct {
	callbackResponse `json:",inline"`
	SubscriptionUrl  string `json:"subscriptionUrl,omitempty"`
}

type SmsCallbackResponse struct {
	callbackResponse `json:",inline"`
	ApplicationUrl   string `json:"applicationUrl,omitempty"`
}

type CallbackReqInfo struct {
	util.CredentialData
	CallbackTimeoutMillis string
	CallbackUrl           string
	CallbackPath          string
	SubscriptionType      subscriptionType
}

type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

type tenantInfo struct {
	tenantId        string
	tenantSubDomain string
}

type GetDependenciesAuthError struct{}

func (err *GetDependenciesAuthError) Error() string {
	return "Not authorized"
}

func (s *SubscriptionHandler) CreateTenant(reqInfo *RequestInfo) *Result {
	util.LogInfo("Create Tenant triggered", TenantProvisioning, "CreateTenant", nil)
	var created, updated = false, false
	var saasData *util.SaasRegistryCredentials
	var smsData *util.SmsCredentials

	// Check if a SubscriptionProvider exists matching the providerSubaccountID and appName
	subPro, err := s.checkSubscriptionProvider(reqInfo.payload.providerSubaccountId, reqInfo.payload.appName)
	if err != nil {
		util.LogError(err, ErrorOccurred, TenantProvisioning, subPro, nil)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	saasData, smsData, err = s.authorizationCheck(reqInfo.headerDetails, subPro, reqInfo.subscriptionType, TenantProvisioning)
	if err != nil {
		util.LogError(err, AuthorizationCheckFailed, TenantProvisioning, subPro, nil)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	// Check if a Subscription resource already exists for this payload
	sub := s.getSubscriptionByAppIdentifier(reqInfo.payload.providerSubaccountId, reqInfo.payload.appName, reqInfo.payload.tenantId, subPro.Namespace, TenantProvisioning).Subscription

	// If the resource doesn't exist, we'll create it
	if sub == nil {
		created = true
		sub, err = s.createSubscription(reqInfo, subPro)
		if err != nil {
			return &Result{Subscription: nil, Message: err.Error()}
		}
	} else {
		// Update the subscription with the new subscription guid, payload and additional context if needed (subscriptionGUID maybe different when a new provisioning request comes in for an existing tenant)
		updated, err = s.updateSubscription(reqInfo, subPro, sub)
		if err != nil {
			return &Result{Subscription: nil, Message: err.Error()}
		}
	}

	if sub != nil {
		tenantIn := tenantInfo{tenantId: reqInfo.payload.tenantId, tenantSubDomain: reqInfo.payload.subdomain}
		callbackReqInfo := s.getCallbackReqInfo(reqInfo.subscriptionType, reqInfo.headerDetails.callbackInfo, saasData, smsData)
		s.initializeCallback(sub.Name, sub.Namespace, subPro, callbackReqInfo, tenantIn, true)
	}

	if created {
		util.LogInfo("Subscription successfully created", TenantProvisioning, subPro, sub, "message", getMessage(created, updated))
	} else if updated {
		util.LogInfo("Subscription successfully updated", TenantProvisioning, subPro, sub, "message", getMessage(created, updated))
	}
	return &Result{Subscription: sub, Message: getMessage(created, updated)}
}

func getMessage(isCreated, isUpdated bool) string {
	// Tenant created/exists
	if isCreated {
		return ResourceCreated
	} else if isUpdated {
		return ResourceUpdated
	} else {
		return ResourceFound
	}
}

func (s *SubscriptionHandler) createSubscription(reqInfo *RequestInfo, subPro *v1alpha1.SubscriptionProvider) (*v1alpha1.Subscription, error) {
	subscriptionGUID := reqInfo.payload.subscriptionGUID
	jsonReqByte, _ := json.Marshal(reqInfo.payload.raw)

	util.LogInfo("Creating subscription", TenantProvisioning, subPro, nil, "tenantId", reqInfo.payload.tenantId, "subscriptionGuid", subscriptionGUID)

	sub, err := s.Clientset.SmeV1alpha1().Subscriptions(subPro.Namespace).Create(context.TODO(), &v1alpha1.Subscription{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: subPro.Name + "-",
			Namespace:    subPro.Namespace,
			Labels: map[string]string{
				LabelAppIdHash:           sha1Sum(reqInfo.payload.providerSubaccountId, reqInfo.payload.appName),
				LabelTenantId:            reqInfo.payload.tenantId,
				MetadataSubscriptionGUID: subscriptionGUID,
			},
		},
		Spec: v1alpha1.SubscriptionSpec{
			AppName:                    reqInfo.payload.appName,
			ProviderSubaccountId:       reqInfo.payload.providerSubaccountId,
			TenantId:                   reqInfo.payload.tenantId,
			Subdomain:                  reqInfo.payload.subdomain,
			SubscriptionGuid:           subscriptionGUID,
			SubscriptionDomain:         reqInfo.subscriptionDomain,
			SubscriptionRequestPayload: string(jsonReqByte),
		},
	}, metav1.CreateOptions{})
	if err != nil || sub == nil {
		util.LogError(err, "Error creating subscription", TenantProvisioning, subPro, nil, "tenantId", reqInfo.payload.tenantId)
		return nil, err
	}

	return sub, nil
}

func (s *SubscriptionHandler) updateSubscription(reqInfo *RequestInfo, subPro *v1alpha1.SubscriptionProvider, sub *v1alpha1.Subscription) (bool, error) {
	jsonReqByte, _ := json.Marshal(reqInfo.payload.raw)

	// Nothing changed --> no update needed
	if sub.Spec.SubscriptionGuid == reqInfo.payload.subscriptionGUID &&
		sub.Spec.SubscriptionDomain == reqInfo.subscriptionDomain &&
		sub.Spec.SubscriptionRequestPayload == string(jsonReqByte) {
		return false, nil
	}

	sub.Spec.SubscriptionGuid = reqInfo.payload.subscriptionGUID
	sub.Spec.SubscriptionDomain = reqInfo.subscriptionDomain
	sub.Spec.SubscriptionRequestPayload = string(jsonReqByte)
	if sub.Labels == nil {
		sub.Labels = map[string]string{}
	}
	sub.Labels[MetadataSubscriptionGUID] = reqInfo.payload.subscriptionGUID

	util.LogInfo("Updating subscription", TenantProvisioning, sub, nil, "tenantId", reqInfo.payload.tenantId, "subscriptionGuid", reqInfo.payload.subscriptionGUID)
	if _, err := s.Clientset.SmeV1alpha1().Subscriptions(subPro.Namespace).Update(context.TODO(), sub, metav1.UpdateOptions{}); err != nil {
		util.LogError(err, "Error updating subscription", TenantProvisioning, sub, nil)
		return false, err
	}

	return true, nil
}

func extractTimeoutInMillis(appUrls string, isSMS bool) string {
	if appUrls == "" {
		return ""
	}

	var appUrlsMap map[string]any
	err := json.Unmarshal([]byte(appUrls), &appUrlsMap)
	if err != nil {
		util.LogError(err, "Error unmarshalling AppUrls", "getCallbackReqInfo", nil, nil)
		return ""
	}

	if isSMS {
		if asyncCallbacks, ok := appUrlsMap["subscriptionCallbacks"].(map[string]any); ok {
			if timeoutInMillis, ok := asyncCallbacks["async"].(map[string]any)["timeoutInMillis"]; ok {
				return fmt.Sprintf("%v", timeoutInMillis)
			}
		}
	} else {
		if timeoutInMillis, ok := appUrlsMap["callbackTimeoutMillis"]; ok {
			return fmt.Sprintf("%v", timeoutInMillis)
		}
	}
	return ""
}

func (s *SubscriptionHandler) getCallbackReqInfo(subscriptionType subscriptionType, callbackPath string, saasData *util.SaasRegistryCredentials, smsData *util.SmsCredentials) *CallbackReqInfo {
	callbackReqInfo := &CallbackReqInfo{
		// Assign subscription type
		SubscriptionType: subscriptionType,
	}

	assignIfNotEmpty := func(target *string, source string) {
		if source != "" {
			*target = source
		}
	}

	// Define a common assigner function
	assignCommonFields := func(source util.CredentialData) {
		assignIfNotEmpty(&callbackReqInfo.CredentialType, source.CredentialType)
		assignIfNotEmpty(&callbackReqInfo.CertificateUrl, source.CertificateUrl)
		assignIfNotEmpty(&callbackReqInfo.Certificate, source.Certificate)
		assignIfNotEmpty(&callbackReqInfo.CertificateKey, source.CertificateKey)
		assignIfNotEmpty(&callbackReqInfo.AuthUrl, source.AuthUrl)
		assignIfNotEmpty(&callbackReqInfo.ClientId, source.ClientId)
		assignIfNotEmpty(&callbackReqInfo.ClientSecret, source.ClientSecret)
	}

	// Assign callback
	assignIfNotEmpty(&callbackReqInfo.CallbackPath, callbackPath)

	switch subscriptionType {
	case SMS:
		if smsData != nil {
			assignCommonFields(smsData.CredentialData)
			assignIfNotEmpty(&callbackReqInfo.CallbackUrl, smsData.SubscriptionManagerUrl)
			callbackReqInfo.CallbackTimeoutMillis = extractTimeoutInMillis(smsData.AppUrls, true)
		}
	default:
		if saasData != nil {
			assignCommonFields(saasData.CredentialData)
			assignIfNotEmpty(&callbackReqInfo.CallbackUrl, saasData.SaasManagerUrl)
			callbackReqInfo.CallbackTimeoutMillis = extractTimeoutInMillis(saasData.AppUrls, false)
		}
	}

	return callbackReqInfo
}

func (s *SubscriptionHandler) getSubscriptionByAppIdentifier(providerSubaccountId, btpAppName, tenantId, namespace, step string) (result *Result) {
	labelsMap := map[string]string{
		LabelTenantId:  tenantId,
		LabelAppIdHash: sha1Sum(providerSubaccountId, btpAppName),
	}

	return s.getSubscriptionByLabels(labelsMap, namespace, step, "getSubscriptionByAppIdentifier")
}

func (s *SubscriptionHandler) getSubscriptionBySubscriptionGUID(subscriptionGUID, tenantId, step string) *Result {
	labelsMap := map[string]string{
		MetadataSubscriptionGUID: subscriptionGUID,
		LabelTenantId:            tenantId,
	}
	return s.getSubscriptionByLabels(labelsMap, metav1.NamespaceAll, step, "getSubscriptionBySubscriptionGUID")
}

func (s *SubscriptionHandler) getSubscriptionByLabels(labelsMap map[string]string, namespace, step, methodName string) *Result {
	labelSelector, err := labels.ValidatedSelectorFromSet(labelsMap)
	if err != nil {
		util.LogError(err, "Error in "+methodName, step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	subList, err := s.Clientset.SmeV1alpha1().Subscriptions(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		util.LogError(err, "Error in "+methodName, step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	if len(subList.Items) == 0 {
		util.LogInfo("No subscription found", step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Subscription: nil, Message: ResourceNotFound}
	}
	// Assume only 1 subscription actually matches the selector!
	util.LogInfo(SubscriptionFound, step, &subList.Items[0], nil, flattenLabels(labelsMap, "namespace", &subList.Items[0].Namespace)...)
	return &Result{Subscription: &subList.Items[0], Message: ResourceFound}
}

func flattenLabels(labelsMap map[string]string, args ...any) []any {
	// Converts the label map to a flat key-value slice for logging
	var result []any
	for k, v := range labelsMap {
		result = append(result, k, v)
	}
	result = append(result, args...)
	return result
}

func (s *SubscriptionHandler) DeleteTenant(reqInfo *RequestInfo) *Result {
	var saasData *util.SaasRegistryCredentials
	var smsData *util.SmsCredentials
	var sub *v1alpha1.Subscription
	var subPro *v1alpha1.SubscriptionProvider
	var err error

	util.LogInfo("Delete Tenant triggered", TenantDeprovisioning, "DeleteTenant", nil)

	// Check if a Subscription exists by subscriptionGUID and tenantId
	sub = s.getSubscriptionBySubscriptionGUID(reqInfo.payload.subscriptionGUID, reqInfo.payload.tenantId, TenantDeprovisioning).Subscription
	if sub != nil {
		subPro, err = s.checkSubscriptionProviderInNamespace(sub.Spec.ProviderSubaccountId, sub.Spec.AppName, sub.Namespace)
		if err != nil {
			util.LogError(err, "SubscriptionProvider not found", TenantDeprovisioning, sub, nil)
			return &Result{Subscription: nil, Message: err.Error()}
		}
	} else if reqInfo.subscriptionType == SaaS {
		subPro, err = s.checkSubscriptionProvider(reqInfo.payload.providerSubaccountId, reqInfo.payload.appName)
		if err != nil {
			util.LogError(err, "SubscriptionProvider not found", TenantDeprovisioning, nil, nil)
			return &Result{Subscription: nil, Message: SubscriptionNotFound}
		}
		// if subscription is not found in SaaS subscription scenario, check if it exists by btpApp identifier to handle cases where it was created without subscriptionGUID
		util.LogInfo("Subscription not found by subscriptionGUID, checking by BTP app identifier", TenantDeprovisioning, "DeleteTenant", nil, "subscriptionGUID", reqInfo.payload.subscriptionGUID)
		sub = s.getSubscriptionByAppIdentifier(subPro.Spec.ProviderSubaccountID, reqInfo.payload.appName, reqInfo.payload.tenantId, metav1.NamespaceAll, TenantDeprovisioning).Subscription
	}

	if sub == nil {
		util.LogWarning("Subscription not found", TenantDeprovisioning)
		return &Result{Subscription: nil, Message: SubscriptionNotFound}
	}

	saasData, smsData, err = s.authorizationCheck(reqInfo.headerDetails, subPro, reqInfo.subscriptionType, TenantDeprovisioning)
	if err != nil {
		util.LogError(err, AuthorizationCheckFailed, TenantDeprovisioning, subPro, nil)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	util.LogInfo(SubscriptionFound, TenantDeprovisioning, subPro, sub)
	err = s.Clientset.SmeV1alpha1().Subscriptions(sub.Namespace).Delete(context.TODO(), sub.Name, metav1.DeleteOptions{})
	if err != nil {
		util.LogError(err, "Error deleting subscription", TenantDeprovisioning, subPro, sub)
		return &Result{Subscription: nil, Message: err.Error()}
	}

	tenantIn := tenantInfo{tenantId: reqInfo.payload.tenantId, tenantSubDomain: reqInfo.payload.subdomain}
	callbackReqInfo := s.getCallbackReqInfo(reqInfo.subscriptionType, reqInfo.headerDetails.callbackInfo, saasData, smsData)
	s.initializeCallback(sub.Name, sub.Namespace, subPro, callbackReqInfo, tenantIn, false)

	return &Result{Subscription: sub, Message: ResourceDeleted}
}

func (s *SubscriptionHandler) authorizationCheck(headerDetails *requestHeaderDetails, subPro *v1alpha1.SubscriptionProvider, subscription subscriptionType, step string) (saasData *util.SaasRegistryCredentials, smsData *util.SmsCredentials, err error) {
	switch subscription {
	case SMS:
		// fetch SMS information
		smsData = s.getSmsDetails(subPro, step)
		if smsData == nil {
			return nil, nil, errors.New(ResourceNotFound)
		}

		// validate certificate issuer and subject
		err = s.checkCertIssuerAndSubject(headerDetails.xForwardedClientCert, smsData, step)

	default:
		var uaaData *util.XSUAACredentials
		// fetch SaaS Registry and XSUAA information
		saasData, uaaData = s.getServiceDetails(subPro, step)
		if saasData == nil || uaaData == nil {
			return nil, nil, errors.New(ResourceNotFound)
		}

		// validate token
		err = s.checkAuthorization(headerDetails.authorization, saasData, uaaData, step)
	}
	return
}

func (s *SubscriptionHandler) checkSubscriptionProvider(providerSubaccountId, btpAppName string) (*v1alpha1.SubscriptionProvider, error) {
	// Find SubscriptionProvider by providerSubaccountId + appName (appIdHash) across all namespaces
	labelSelector, _ := labels.ValidatedSelectorFromSet(map[string]string{
		LabelAppIdHash: sha1Sum(providerSubaccountId, btpAppName),
	})

	return s.getSubscriptionProviderByLabelSelector(metav1.NamespaceAll, labelSelector)
}

func (s *SubscriptionHandler) checkSubscriptionProviderInNamespace(providerSubaccountId, btpAppName, namespace string) (*v1alpha1.SubscriptionProvider, error) {
	// Find SubscriptionProvider by providerSubaccountId + appName (appIdHash) in a specific namespace
	labelSelector, _ := labels.ValidatedSelectorFromSet(map[string]string{
		LabelAppIdHash: sha1Sum(providerSubaccountId, btpAppName),
	})

	return s.getSubscriptionProviderByLabelSelector(namespace, labelSelector)
}

func (s *SubscriptionHandler) getSubscriptionProviderByLabelSelector(namespace string, labelSelector labels.Selector) (*v1alpha1.SubscriptionProvider, error) {
	subProList, err := s.Clientset.SmeV1alpha1().SubscriptionProviders(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		return nil, err
	}
	if len(subProList.Items) == 0 {
		return nil, errors.New(ResourceNotFound)
	}
	// Assume only 1 provider actually matches the selector!
	return &subProList.Items[0], nil
}

func (s *SubscriptionHandler) checkAuthorization(authHeader string, saasData *util.SaasRegistryCredentials, uaaData *util.XSUAACredentials, step string) error {
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return errors.New("expected bearer token")
	}

	token := authHeader[7:]
	err := VerifyXSUAAJWTToken(context.TODO(), token, &XSUAAConfig{
		UAADomain: saasData.UAADomain,
		ClientID:  saasData.ClientId,
		XSAppName: uaaData.XSAppName,
		// `.Callback` is the scope usually used by approuter and `.mtcallback` is used by CAP. Either one of these may be present.
		ExpectedScopes: []string{uaaData.XSAppName + ".Callback", uaaData.XSAppName + ".mtcallback"},
	}, s.httpClientGenerator.NewHTTPClient())
	if err != nil {
		util.LogError(err, "failed token validation", step, "checkAuthorization", nil, "XSAppName", uaaData.XSAppName)
		return errors.New(AuthorizationCheckFailed)
	}
	return nil
}

func (s *SubscriptionHandler) checkCertIssuerAndSubject(xForwardedClientCert string, smsData *util.SmsCredentials, step string) error {
	const checkCertIssuerAndSubjectFailed = "certificate issuer and subject check failed"

	if err := checkCertificate(xForwardedClientCert, smsData.CallbackCertificateIssuer, smsData.CallbackCertificateSubject); err != nil {
		util.LogError(err, checkCertIssuerAndSubjectFailed, step, "checkCertIssuerAndSubject", nil)
		return err
	}
	return nil
}

func (s *SubscriptionHandler) initializeCallback(subName, subNamespace string, subPro *v1alpha1.SubscriptionProvider, callbackReqInfo *CallbackReqInfo, tenantIn tenantInfo, isProvisioning bool) {
	step := TenantProvisioning
	if !isProvisioning {
		step = TenantDeprovisioning
	}
	util.LogInfo("Callback initialized", step, subPro, nil, "async callback path", callbackReqInfo.CallbackPath, "subscription", subName)

	go func() {
		// create a context for subscription checks and outgoing requests
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Check subscription status asynchronously
		util.LogInfo("Starting subscription status check", step, subPro, nil, "subscription", subName)
		status, appUrl := s.checkSubscriptionStatus(ctx, subNamespace, subName, isProvisioning, callbackReqInfo.CallbackTimeoutMillis)
		util.LogInfo("Subscription status check complete", step, subPro, nil, "subscription", subName, "status", status, "subscription URL", appUrl)

		additionalOutput := &map[string]any{}
		if isProvisioning {
			saasAdditionalOutput := subPro.Annotations[AnnotationSaaSAdditionalOutput]
			if saasAdditionalOutput != "" {
				// Add additional output to the callback response
				err := json.Unmarshal([]byte(saasAdditionalOutput), additionalOutput)
				if err != nil {
					util.LogError(err, "Error parsing additional output", step, subPro, nil, "annotation value", saasAdditionalOutput)
					additionalOutput = nil
				}
			}
			// Add tenant data to the additional output if it exists
			err := s.enrichAdditionalOutput(subPro.Namespace, tenantIn.tenantId, additionalOutput)
			if err != nil {
				util.LogError(err, "Error updating tenant data", step, subPro, nil, "tenantId", tenantIn.tenantId)
			}
		} else {
			additionalOutput = nil
		}

		s.handleAsyncCallback(ctx, callbackReqInfo, status, callbackReqInfo.CallbackPath, appUrl, additionalOutput, isProvisioning)
	}()
}

func (s *SubscriptionHandler) enrichAdditionalOutput(namespace string, tenantId string, additionalOutput *map[string]any) error {
	labelSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelTenantId: tenantId,
	})
	if err != nil {
		return err
	}

	tenantDataList, err := s.Clientset.SmeV1alpha1().CAPTenantOutputs(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		return err
	}

	for _, tenantData := range tenantDataList.Items {
		// Update relevant data from each CAPTenantOutput to async callback additional output
		tenantDataOutput := &map[string]any{}
		err = json.Unmarshal([]byte(tenantData.Spec.SubscriptionCallbackData), tenantDataOutput)
		if err != nil {
			return err
		}
		// merge tenant data output into additional output
		maps.Copy((*additionalOutput), *tenantDataOutput)
	}
	return nil
}

func (s *SubscriptionHandler) checkSubscriptionStatus(ctx context.Context, subNamespace string, subName string, provisioning bool, callbackTimeoutMs string) (ready bool, url string) {
	asyncCallbackTimeout := 15 * time.Minute
	if callbackTimeoutMs != "" {
		asyncCallbackTimeout, _ = time.ParseDuration(callbackTimeoutMs + "ms")
	}

	step := TenantProvisioning
	if !provisioning {
		step = TenantDeprovisioning
	}

	timedCtx, cancel := context.WithTimeout(ctx, asyncCallbackTimeout) // Assume subscriptions won't take over 15mins to be "Ready"
	defer cancel()

	for {
		select {
		case <-timedCtx.Done():
			klog.Warningf("subscription status check: %s", timedCtx.Err().Error())
			return false, ""
		default:
			sub, err := s.Clientset.SmeV1alpha1().Subscriptions(subNamespace).Get(context.TODO(), subName, metav1.GetOptions{})
			if k8sErrors.IsNotFound(err) {
				util.LogInfo("No subscription found.. Exiting subscription status check.", step, "Subscription Status Check", nil, "subscription", subName, "namespace", subNamespace)
				if !provisioning {
					return true, ""
				}
			}
			if sub != nil {
				util.LogInfo(SubscriptionFound, step, sub, nil, "tenantid", sub.Spec.TenantId, "status", sub.Status.State)
				if provisioning && (sub.Status.State == v1alpha1.SubscriptionStateReady || sub.Status.State == v1alpha1.SubscriptionStateError) {
					util.LogInfo("Exiting subscription status check", step, sub, nil, "tenantid", sub.Spec.TenantId, "status", sub.Status.State)
					return sub.Status.State == v1alpha1.SubscriptionStateReady, sub.Status.Url
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (s *SubscriptionHandler) getServiceDetails(subPro *v1alpha1.SubscriptionProvider, step string) (saasData *util.SaasRegistryCredentials, uaaData *util.XSUAACredentials) {
	var wg sync.WaitGroup

	wg.Go(func() {
		saasData = s.getSaasDetails(subPro, step)
	})
	wg.Go(func() {
		uaaData = s.getXSUAADetails(subPro, step)
	})

	wg.Wait()
	return saasData, uaaData
}

func (s *SubscriptionHandler) getSaasDetails(subPro *v1alpha1.SubscriptionProvider, step string) *util.SaasRegistryCredentials {
	secret := subPro.Spec.SubscriptionInfo.SubscriptionSecret
	info := &v1alpha1.ServiceInfo{Name: secret, Secret: secret}
	result, err := util.ReadServiceCredentialsFromSecret[util.SaasRegistryCredentials](info, subPro.Namespace, s.KubeClientset, false)
	if err != nil {
		util.LogError(err, "SaaS Registry credentials could not be read. Exiting..", step, subPro, nil)
	}
	return result
}

func (s *SubscriptionHandler) getXSUAADetails(subPro *v1alpha1.SubscriptionProvider, step string) *util.XSUAACredentials {
	secret := subPro.Spec.SubscriptionInfo.AuthSecret
	if secret == "" {
		util.LogError(fmt.Errorf("no auth secret configured in SubscriptionProvider %s.%s", subPro.Namespace, subPro.Name), "XSUAA credentials could not be read. Exiting..", step, subPro, nil)
		return nil
	}
	info := &v1alpha1.ServiceInfo{Name: secret, Secret: secret}
	result, err := util.ReadServiceCredentialsFromSecret[util.XSUAACredentials](info, subPro.Namespace, s.KubeClientset, false)
	if err != nil {
		util.LogError(err, "XSUAA credentials could not be read. Exiting..", step, subPro, nil)
	}
	return result
}

func (s *SubscriptionHandler) getSmsDetails(subPro *v1alpha1.SubscriptionProvider, step string) *util.SmsCredentials {
	secret := subPro.Spec.SubscriptionInfo.SubscriptionSecret
	info := &v1alpha1.ServiceInfo{Name: secret, Secret: secret}
	result, err := util.ReadServiceCredentialsFromSecret[util.SmsCredentials](info, subPro.Namespace, s.KubeClientset, false)
	if err != nil {
		util.LogError(err, "SMS credentials could not be read. Exiting..", step, subPro, nil)
	}
	return result
}

func prepareTokenRequest(ctx context.Context, callbackReqInfo *CallbackReqInfo, client *http.Client) (tokenReq *http.Request, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error preparing token request: %w", err)
		}
	}()
	var (
		tokenURL string
	)
	if callbackReqInfo.CredentialType == "x509" {
		tokenURL = callbackReqInfo.CertificateUrl + "/oauth/token"

		// setup client for mTLS
		cert, err := tls.X509KeyPair([]byte(callbackReqInfo.Certificate), []byte(callbackReqInfo.CertificateKey))
		if err != nil {
			return nil, err
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM([]byte(callbackReqInfo.Certificate))
		tlsConfig := &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{cert},
		}
		if t, ok := client.Transport.(*http.Transport); ok {
			t.TLSClientConfig = tlsConfig
		} else {
			client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
		}
	} else {
		tokenURL = callbackReqInfo.AuthUrl + "/oauth/token"
	}
	tokenData := url.Values{}
	tokenData.Add("client_id", callbackReqInfo.ClientId)
	tokenData.Add("grant_type", "client_credentials")

	tokenReq, err = http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, err
	}
	tokenReq.Header.Set(ContentType, "application/x-www-form-urlencoded")
	if callbackReqInfo.CredentialType != "x509" {
		tokenReq.Header.Set("Authorization", BasicPrefix+base64.StdEncoding.EncodeToString([]byte(callbackReqInfo.ClientId+":"+callbackReqInfo.ClientSecret)))
	}

	return tokenReq, nil
}

func (s *SubscriptionHandler) handleAsyncCallback(ctx context.Context, callbackReqInfo *CallbackReqInfo, status bool, asyncCallbackPath string, appUrl string, additionalOutput *map[string]any, isProvisioning bool) {
	// Get OAuth token
	tokenClient := s.httpClientGenerator.NewHTTPClient()
	tokenReq, err := prepareTokenRequest(ctx, callbackReqInfo, tokenClient)
	if err != nil {
		klog.ErrorS(err, ErrorOccurred)
		return
	}
	klog.V(2).InfoS("Triggering OAuth", "request", tokenReq)

	tokenResponse, err := tokenClient.Do(tokenReq)
	if err != nil {
		klog.ErrorS(err, "Error getting token for async callback")
		return
	}

	klog.V(2).InfoS("Obtained token for async callback", "response", tokenResponse)
	// Get the relevant OAuth request
	decoder := json.NewDecoder(tokenResponse.Body)
	var oAuthType OAuthResponse
	err = decoder.Decode(&oAuthType)
	if err != nil {
		klog.ErrorS(err, "Error parsing token for async callback")
		return
	}
	defer tokenResponse.Body.Close()

	checkMatch := func(match bool, trueVal string, falseVal string) string {
		if match {
			return trueVal
		}
		return falseVal
	}

	var payload []byte
	callbackResponse := &callbackResponse{
		Status:           checkMatch(status, CallbackSucceeded, CallbackFailed),
		Message:          checkMatch(status, checkMatch(isProvisioning, ProvisioningSucceededMessage, DeprovisioningSucceededMessage), checkMatch(isProvisioning, ProvisioningFailedMessage, DeprovisioningFailedMessage)),
		AdditionalOutput: additionalOutput,
	}

	switch callbackReqInfo.SubscriptionType {
	case SMS:
		payload, _ = json.Marshal(&SmsCallbackResponse{
			callbackResponse: *callbackResponse,
			ApplicationUrl:   appUrl,
		})
	default:
		payload, _ = json.Marshal(&SaaSCallbackResponse{
			callbackResponse: *callbackResponse,
			SubscriptionUrl:  appUrl,
		})
	}

	callbackReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, callbackReqInfo.CallbackUrl+asyncCallbackPath, bytes.NewBuffer(payload))
	callbackReq.Header.Set(ContentType, "application/json")
	callbackReq.Header.Set("Authorization", BearerPrefix+oAuthType.AccessToken)

	client := s.httpClientGenerator.NewHTTPClient()
	klog.V(2).InfoS("Triggering callback", "request", callbackReq)

	callbackRes, err := client.Do(callbackReq)
	if err != nil {
		klog.ErrorS(err, "Error sending async callback")
		return
	} else {
		klog.InfoS("Async callback done", "response", callbackRes.Body, "status", callbackRes.Status)
		defer callbackRes.Body.Close()
	}

	klog.InfoS("Exiting from async callback..")
}

func (s *SubscriptionHandler) HandleRequest(w http.ResponseWriter, req *http.Request, subscriptionType subscriptionType) {
	var subscriptionResult *Result
	// Always return a response
	defer func() {
		subscriptionResult.Subscription = nil // Don't return subscription details in response
		res, _ := json.Marshal(subscriptionResult)
		w.Write(res)
	}()

	if req.Method != http.MethodPut && req.Method != http.MethodDelete {
		subscriptionResult = &Result{Subscription: nil, Message: InvalidRequestMethod}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Decode the request to get tenant details
	reqInfo, err := ProcessRequest(req, subscriptionType)
	if err != nil || reqInfo == nil {
		w.WriteHeader(http.StatusBadRequest)
		subscriptionResult = &Result{Subscription: nil, Message: err.Error()}
		return
	}

	switch req.Method {
	case http.MethodPut:
		subscriptionResult = s.CreateTenant(reqInfo)
		if subscriptionResult.Subscription == nil {
			w.WriteHeader(http.StatusNotAcceptable)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	case http.MethodDelete:
		subscriptionResult = s.DeleteTenant(reqInfo)
		if subscriptionResult.Message == SubscriptionNotFound {
			w.WriteHeader(http.StatusNotFound)
		} else if subscriptionResult.Message != ResourceDeleted {
			w.WriteHeader(http.StatusNotAcceptable)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

func (s *SubscriptionHandler) HandleSaaSRequest(w http.ResponseWriter, req *http.Request) {
	s.HandleRequest(w, req, SaaS)
}

func (s *SubscriptionHandler) HandleSMSRequest(w http.ResponseWriter, req *http.Request) {
	s.HandleRequest(w, req, SMS)
}

func ProcessRequest(req *http.Request, subscriptionType subscriptionType) (*RequestInfo, error) {
	var subscriptionGUID, tenantId, subdomain, globalAccountId, providerSubaccountId, appName, subscriptionDomain string
	var jsonPayload map[string]any

	if !(req.Method == http.MethodDelete && subscriptionType == SMS) {
		decoder := json.NewDecoder(req.Body)
		err := decoder.Decode(&jsonPayload)
		if err != nil {
			return nil, fmt.Errorf("error decoding request: %w", err)
		}
	}

	var headerDetails requestHeaderDetails
	headerDetails.callbackInfo = req.Header.Get("STATUS_CALLBACK")
	switch subscriptionType {
	case SMS:
		headerDetails.xForwardedClientCert = req.Header.Get("X-Forwarded-Client-Cert")

		switch req.Method {
		case http.MethodPut:
			subscriber := jsonPayload["subscriber"].(map[string]any)
			subscriptionGUID = subscriber["subscriptionGUID"].(string)
			tenantId = subscriber["app_tid"].(string)
			subdomain = subscriber["subaccountSubdomain"].(string)
			globalAccountId = subscriber["globalAccountId"].(string)
			rootApp := jsonPayload["rootApplication"].(map[string]any)
			providerSubaccountId = rootApp["providerSubaccountId"].(string)
			appName = rootApp["appName"].(string)
			subscriptionDomain = getSubscriptionDomain(rootApp)
		case http.MethodDelete:
			// get parameter from URL
			subscriptionGUID = req.URL.Query().Get("subscriptionGUID")
			if subscriptionGUID == "" {
				return nil, fmt.Errorf("subscriptionGUID is missing in the request URL")
			}

			tenantId = strings.TrimPrefix(req.URL.Path, "/sms/provision/tenants/")
			if tenantId == "" {
				return nil, fmt.Errorf("tenantId is missing in the request URL")
			}
		}

	default:
		headerDetails.authorization = req.Header.Get("Authorization")

		subscriptionGUID = jsonPayload["subscriptionGUID"].(string)
		tenantId = jsonPayload["subscribedTenantId"].(string)
		subdomain = jsonPayload["subscribedSubdomain"].(string)
		globalAccountId = jsonPayload["globalAccountGUID"].(string)
		providerSubaccountId = jsonPayload["providerSubaccountId"].(string)
		appName = jsonPayload["subscriptionAppName"].(string)
		subscriptionDomain = getSubscriptionDomain(jsonPayload)
	}

	//subscription and tenant identifiers extracted from the incoming request
	payload := &payloadDetails{
		// GTID
		subscriptionGUID:     subscriptionGUID,
		tenantId:             tenantId,
		subdomain:            subdomain,
		globalAccountId:      globalAccountId,
		providerSubaccountId: providerSubaccountId,
		appName:              appName,
		raw:                  &jsonPayload,
	}
	return &RequestInfo{
		subscriptionType:   subscriptionType,
		subscriptionDomain: subscriptionDomain,
		payload:            payload,
		headerDetails:      &headerDetails,
	}, nil
}

func getSubscriptionDomain(payload map[string]any) string {
	if subscriptionParams, ok := payload["subscriptionParams"]; ok {
		if subscriptionParamsMap, ok := subscriptionParams.(map[string]any); ok {
			if subscriptionDomain, ok := subscriptionParamsMap["subscriptionDomain"]; ok {
				return subscriptionDomain.(string)
			}
		}
	}
	return ""
}

func (s *SubscriptionHandler) getDependencies(req *http.Request, subscriptionType subscriptionType) ([]byte, error) {
	// Read the subscription provider by using the provider subaccount id & app-name passed in the URI
	// URI format - /dependencies/providersubaccountId/app-name or /sms/dependencies/providersubaccountId/app-name/{app_tid}
	providersubaccountId := req.PathValue("providerSubaccountId")
	appName := req.PathValue("appName")
	if providersubaccountId == "" || appName == "" {
		err := errors.New("missing providerSubaccountId or appName in request URI")
		util.LogError(err, "Missing providerSubaccountId or appName in request URI", GetDependencies, nil, nil, "uri", req.RequestURI)
		return nil, err
	}

	util.LogInfo("Get dependencies request received", GetDependencies, nil, nil, "subscriptionType", subscriptionType, "providerSubaccountId", providersubaccountId, "btpAppName", appName)

	subPro, err := s.checkSubscriptionProvider(providersubaccountId, appName)
	if err != nil {
		util.LogError(err, "SubscriptionProvider not found for providerSubaccountId and appName", GetDependencies, nil, nil, "providerSubaccountId", providersubaccountId, "btpAppName", appName)
		return nil, err
	}

	var headerDetails requestHeaderDetails
	switch subscriptionType {
	case SMS:
		headerDetails.xForwardedClientCert = req.Header.Get("X-Forwarded-Client-Cert")
	default:
		headerDetails.authorization = req.Header.Get("Authorization")
	}

	if _, _, err = s.authorizationCheck(&headerDetails, subPro, subscriptionType, GetDependencies); err != nil {
		util.LogError(err, "Authorization check failed for get dependencies request", GetDependencies, subPro, nil, "subscriptionType", subscriptionType)
		return nil, &GetDependenciesAuthError{}
	}

	// Dependencies are precomputed by the controller and published to the SubscriptionProvider status
	if subPro.Status.Dependencies == "" {
		util.LogInfo("No subscription dependencies found", GetDependencies, subPro, nil)
		return nil, nil
	}

	util.LogInfo("Subscription dependencies resolved", GetDependencies, subPro, nil, "dependencies", subPro.Status.Dependencies)

	return []byte(subPro.Status.Dependencies), nil
}

func (s *SubscriptionHandler) handleGetDependenciesRequest(w http.ResponseWriter, req *http.Request, subscriptionType subscriptionType) {
	switch req.Method {
	case http.MethodGet:
		dependencies, err := s.getDependencies(req, subscriptionType)
		if err != nil {
			if _, ok := err.(*GetDependenciesAuthError); ok {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		} else {
			w.Header().Set(ContentType, "application/json")
			w.Write(dependencies)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *SubscriptionHandler) HandleSaaSGetDependenciesRequest(w http.ResponseWriter, req *http.Request) {
	s.handleGetDependenciesRequest(w, req, SaaS)
}

func (s *SubscriptionHandler) HandleSMSGetDependenciesRequest(w http.ResponseWriter, req *http.Request) {
	s.handleGetDependenciesRequest(w, req, SMS)
}

func NewSubscriptionHandler(clientset versioned.Interface, kubeClientset kubernetes.Interface) *SubscriptionHandler {
	return &SubscriptionHandler{Clientset: clientset, KubeClientset: kubeClientset, httpClientGenerator: &httpClientGeneratorImpl{}}
}

// Returns an sha1 checksum for a given source string
func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}
