/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	AnnotationSubscriptionContextSecret = "sme.sap.com/subscription-context-secret"
	AnnotationSaaSAdditionalOutput      = "sme.sap.com/saas-additional-output"
	AnnotationSubscriptionDomain        = "sme.sap.com/subscription-domain"
)

const (
	LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"
	LabelTenantId                     = "sme.sap.com/btp-tenant-id"
	LabelGlobalTenantId               = "sme.sap.com/btp-global-tenant-id"
)

const (
	ResourceCreated  = "resource created successfully"
	ResourceFound    = "resource exists"
	ResourceDeleted  = "resource deleted successfully"
	ResourceNotFound = "resource not found"
	TenantNotFound   = "tenant not found"
)

const ErrorOccurred = "Error occurred "
const InvalidRequestMethod = "invalid request method"
const AuthorizationCheckFailed = "authorization check failed"
const BearerPrefix = "Bearer "
const BasicPrefix = "Basic "

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
)

type RequestInfo struct {
	// One of "SMS" or "SaaS"
	subscriptionType subscriptionType
	// payload Details
	payload *payloadDetails
	// header details
	headerDetails *headerDetails
}

type subscriptionType string

const (
	SaaS subscriptionType = "SaaS"
	SMS  subscriptionType = "SMS"
)

type payloadDetails struct {
	subscriptionGUID  string
	tenantId          string
	subdomain         string
	globalAccountId   string
	appName           string
	commercialAppName string
	raw               *map[string]any
}

type headerDetails struct {
	authorization        string
	callbackInfo         string
	xForwardedClientCert string
}

type Result struct {
	Tenant  *v1alpha1.CAPTenant
	Message string
}

type SubscriptionHandler struct {
	Clientset           versioned.Interface
	KubeClienset        kubernetes.Interface
	httpClientGenerator httpClientGenerator
}
type SaaSCallbackResponse struct {
	Status           string          `json:"status"`
	Message          string          `json:"message"`
	SubscriptionUrl  string          `json:"subscriptionUrl"`
	AdditionalOutput *map[string]any `json:"additionalOutput,omitempty"`
}

type SmsCallbackResponse struct {
	Status           string          `json:"status"`
	Message          string          `json:"message"`
	ApplicationUrl   string          `json:"applicationUrl"`
	AdditionalOutput *map[string]any `json:"additionalOutput,omitempty"`
}

type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

type tenantInfo struct {
	tenantId        string
	tenantSubDomain string
}

func (s *SubscriptionHandler) CreateTenant(reqInfo *RequestInfo) *Result {
	util.LogInfo("Create Tenant triggered", TenantProvisioning, "CreateTenant", nil)
	var created = false
	var saasData *util.SaasRegistryCredentials
	var uaaData *util.XSUAACredentials
	var smsData *util.SmsCredentials

	// Check if CAPApplication instance for the given btpApp exists
	ca, err := s.checkCAPApp(reqInfo.payload.globalAccountId, reqInfo.payload.appName)
	if err != nil {
		util.LogError(err, ErrorOccurred, TenantProvisioning, ca, nil)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	switch reqInfo.subscriptionType {
	case SMS:
		// fetch SMS information
		smsData = s.getSmsDetails(ca, TenantProvisioning)
		if smsData == nil {
			return &Result{Tenant: nil, Message: ResourceNotFound}
		}

		err = s.checkCertIssuerAndSubject(reqInfo.headerDetails.xForwardedClientCert, smsData, TenantProvisioning)
		if err != nil {
			return &Result{Tenant: nil, Message: err.Error()}
		}

	default:
		// fetch SaaS Registry and XSUAA information
		saasData, uaaData = s.getServiceDetails(ca, TenantProvisioning)
		if saasData == nil || uaaData == nil {
			return &Result{Tenant: nil, Message: ResourceNotFound}
		}

		// validate token
		err = s.checkAuthorization(reqInfo.headerDetails.authorization, saasData, uaaData, TenantProvisioning)
		if err != nil {
			return &Result{Tenant: nil, Message: err.Error()}
		}
	}

	// Check if A CRO for CAPTenant already exists
	tenant := s.getTenantByBtpAppIdentifier(reqInfo.payload.globalAccountId, reqInfo.payload.appName, reqInfo.payload.tenantId, ca.Namespace, TenantProvisioning).Tenant

	// If the resource doesn't exist, we'll create it
	if tenant == nil {
		created = true
		jsonReqByte, _ := json.Marshal(reqInfo.payload.raw)
		// Create a secret to store the subscription context (payload from the request)
		secret, err := s.KubeClienset.CoreV1().Secrets(ca.Namespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: ca.Name + "-consumer-",
				Namespace:    ca.Namespace,
				Labels: map[string]string{
					LabelBTPApplicationIdentifierHash: sha1Sum(reqInfo.payload.globalAccountId, reqInfo.payload.appName),
					LabelTenantId:                     reqInfo.payload.tenantId,
					LabelGlobalTenantId:               reqInfo.payload.subscriptionGUID,
				},
			},
			StringData: map[string]string{
				"subscriptionContext": string(jsonReqByte),
			},
		}, metav1.CreateOptions{})
		if err != nil {
			// Log error and exit if secret creation fails
			util.LogError(err, "Error creating subscripion context secret", TenantProvisioning, ca, nil)
			return &Result{Tenant: nil, Message: err.Error()}
		}
		util.LogInfo("Creating tenant", TenantProvisioning, ca, nil)
		tenant, _ = s.Clientset.SmeV1alpha1().CAPTenants(ca.Namespace).Create(context.TODO(), &v1alpha1.CAPTenant{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: ca.Name + "-",
				Namespace:    ca.Namespace,
				Annotations: map[string]string{
					AnnotationSubscriptionContextSecret: secret.Name, // Store the secret name in the tenant annotation
				},
				Labels: map[string]string{
					LabelBTPApplicationIdentifierHash: sha1Sum(reqInfo.payload.globalAccountId, reqInfo.payload.appName),
					LabelTenantId:                     reqInfo.payload.tenantId,
					LabelGlobalTenantId:               reqInfo.payload.subscriptionGUID,
				},
			},
			Spec: v1alpha1.CAPTenantSpec{
				CAPApplicationInstance: ca.Name,
				BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
					SubDomain: reqInfo.payload.subdomain,
					TenantId:  reqInfo.payload.tenantId,
				},
			},
		}, metav1.CreateOptions{})

		// Log error and exit if secret updation fails
		err = s.updateSecret(tenant, secret)
		if err != nil {
			return &Result{Tenant: nil, Message: err.Error()}
		}
	}

	// TODO: consider retrying tenant creation if it is in Error state
	if tenant != nil {
		tenantIn := tenantInfo{tenantId: reqInfo.payload.tenantId, tenantSubDomain: reqInfo.payload.subdomain}
		callbackReqInfo := s.getCallbackReqInfo(reqInfo.subscriptionType, reqInfo.headerDetails.callbackInfo, saasData, smsData)
		s.initializeCallback(tenant.Name, ca, callbackReqInfo, reqInfo.subscriptionType, tenantIn, true)
	}

	// Tenant created/exists
	message := func(isCreated bool) string {
		if isCreated {
			return ResourceCreated
		} else {
			return ResourceFound
		}
	}
	util.LogInfo("Tenant successfully created", TenantProvisioning, ca, tenant, "message", message(created))
	return &Result{Tenant: tenant, Message: message(created)}
}

func (s *SubscriptionHandler) getCallbackReqInfo(subscriptionType subscriptionType, callbackPath string, saasData *util.SaasRegistryCredentials, smsData *util.SmsCredentials) *util.CallbackReqInfo {
	var callbackReqInfo = &util.CallbackReqInfo{}

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

	parseAppUrls := func(appUrls string, isSMS bool) {
		if appUrls == "" {
			return
		}

		var appUrlsMap map[string]any
		err := json.Unmarshal([]byte(appUrls), &appUrlsMap)
		if err != nil {
			util.LogError(err, "Error unmarshalling AppUrls", "getCallbackReqInfo", nil, nil)
			return
		}

		if isSMS {
			if asyncCallbacks, ok := appUrlsMap["subscriptionCallbacks"].(map[string]any); ok {
				if timeoutInMillis, ok := asyncCallbacks["async"].(map[string]any)["timeoutInMillis"]; ok {
					callbackReqInfo.CallbackTimeoutMillis = fmt.Sprintf("%v", timeoutInMillis)
				}
			}
		} else {
			if timeoutInMillis, ok := appUrlsMap["callbackTimeoutMillis"]; ok {
				callbackReqInfo.CallbackTimeoutMillis = fmt.Sprintf("%v", timeoutInMillis)
			}
		}
	}

	// Assign callback
	assignIfNotEmpty(&callbackReqInfo.CallbackPath, callbackPath)

	switch subscriptionType {
	case SMS:
		if smsData != nil {
			assignCommonFields(smsData.CredentialData)
			assignIfNotEmpty(&callbackReqInfo.CallbackUrl, smsData.SubscriptionManagerUrl)
			parseAppUrls(smsData.AppUrls, true)
		}
	default:
		if saasData != nil {
			assignCommonFields(saasData.CredentialData)
			assignIfNotEmpty(&callbackReqInfo.CallbackUrl, saasData.SaasManagerUrl)
			parseAppUrls(saasData.AppUrls, false)
		}
	}

	return callbackReqInfo
}

func (s *SubscriptionHandler) updateSecret(tenant *v1alpha1.CAPTenant, secret *corev1.Secret) error {
	if tenant != nil {
		secret.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(tenant, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind)),
		}
		_, err := s.KubeClienset.CoreV1().Secrets(tenant.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			util.LogError(err, "Error updating payload tenant subscription secret", TenantProvisioning, tenant, secret)
			return err
		}
	}
	return nil
}

func (s *SubscriptionHandler) getTenantByBtpAppIdentifier(globalAccountGUID, btpAppName, tenantId, namespace, step string) *Result {
	labelsMap := map[string]string{
		LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountGUID, btpAppName),
		LabelTenantId:                     tenantId,
	}
	return s.getTenantByLabels(labelsMap, namespace, step, "getTenantByBtpAppIdentifier")
}

func (s *SubscriptionHandler) getTenantBySubscriptionGUID(subscriptionGUID, tenantId, step string) *Result {
	labelsMap := map[string]string{
		LabelGlobalTenantId: subscriptionGUID,
		LabelTenantId:       tenantId,
	}
	return s.getTenantByLabels(labelsMap, metav1.NamespaceAll, step, "getTenantBySubscriptionGUID")
}

func (s *SubscriptionHandler) getTenantByLabels(labelsMap map[string]string, namespace, step, methodName string) *Result {
	labelSelector, err := labels.ValidatedSelectorFromSet(labelsMap)
	if err != nil {
		util.LogError(err, "Error in "+methodName, step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	ctList, err := s.Clientset.SmeV1alpha1().CAPTenants(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		util.LogError(err, "Error in "+methodName, step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	if len(ctList.Items) == 0 {
		util.LogInfo("No tenant found", step, methodName, nil, flattenLabels(labelsMap)...)
		return &Result{Tenant: nil, Message: ResourceNotFound}
	}
	// Assume only 1 tenant actually matches the selector!
	util.LogInfo("Tenant found", step, &ctList.Items[0], nil, append([]interface{}{"namespace", &ctList.Items[0].Namespace}, flattenLabels(labelsMap)...)...)
	return &Result{Tenant: &ctList.Items[0], Message: ResourceFound}
}

func flattenLabels(labelsMap map[string]string) []interface{} {
	// Converts the label map to a flat key-value slice for logging
	var result []interface{}
	for k, v := range labelsMap {
		result = append(result, k, v)
	}
	return result
}

func (s *SubscriptionHandler) DeleteTenant(reqInfo *RequestInfo) *Result {
	var saasData *util.SaasRegistryCredentials
	var uaaData *util.XSUAACredentials
	var smsData *util.SmsCredentials
	var tenant *v1alpha1.CAPTenant
	var ca *v1alpha1.CAPApplication
	var err error

	util.LogInfo("Delete Tenant triggered", TenantDeprovisioning, "DeleteTenant", nil)

	switch reqInfo.subscriptionType {
	case SMS:
		// Check if tenant exists by subscriptionGUID and tenantId
		tenant = s.getTenantBySubscriptionGUID(reqInfo.payload.subscriptionGUID, reqInfo.payload.tenantId, TenantDeprovisioning).Tenant
		if tenant == nil {
			util.LogWarning("CAPTenant not found", TenantDeprovisioning)
			return &Result{Tenant: nil, Message: TenantNotFound}
		}

		ca, err = s.Clientset.SmeV1alpha1().CAPApplications(tenant.Namespace).Get(context.TODO(), tenant.Spec.CAPApplicationInstance, metav1.GetOptions{})
		if err != nil {
			util.LogError(err, "CAPApplication not found", TenantDeprovisioning, tenant, nil)
			return &Result{Tenant: nil, Message: err.Error()}
		}

		// fetch SMS information
		smsData = s.getSmsDetails(ca, TenantDeprovisioning)
		if smsData == nil {
			return &Result{Tenant: nil, Message: ResourceNotFound}
		}

		err = s.checkCertIssuerAndSubject(reqInfo.headerDetails.xForwardedClientCert, smsData, TenantDeprovisioning)
		if err != nil {
			return &Result{Tenant: nil, Message: err.Error()}
		}

	default:
		// Check if tenant exists by subscriptionGUID and tenantId
		tenant = s.getTenantBySubscriptionGUID(reqInfo.payload.subscriptionGUID, reqInfo.payload.tenantId, TenantDeprovisioning).Tenant
		if tenant == nil {
			// if tenant is not found, check if it exists by btpApp identifier to handle cases where tenant was created without subscriptionGUID
			util.LogInfo("Tenant not found by subscriptionGUID, checking by BTP app identifier", TenantDeprovisioning, "DeleteTenant", nil, "subscriptionGUID", reqInfo.payload.subscriptionGUID)
			tenant = s.getTenantByBtpAppIdentifier(reqInfo.payload.globalAccountId, reqInfo.payload.appName, reqInfo.payload.tenantId, metav1.NamespaceAll, TenantDeprovisioning).Tenant
			if tenant == nil {
				util.LogWarning("CAPTenant not found", TenantDeprovisioning)
				return &Result{Tenant: nil, Message: TenantNotFound}
			}
		}

		ca, err = s.Clientset.SmeV1alpha1().CAPApplications(tenant.Namespace).Get(context.TODO(), tenant.Spec.CAPApplicationInstance, metav1.GetOptions{})
		if err != nil {
			util.LogError(err, "CAPApplication not found", TenantDeprovisioning, tenant, nil)
			return &Result{Tenant: nil, Message: err.Error()}
		}

		// fetch SaaS Registry and XSUAA information
		saasData, uaaData = s.getServiceDetails(ca, TenantDeprovisioning)
		if saasData == nil || uaaData == nil {
			return &Result{Tenant: nil, Message: ResourceNotFound}
		}

		// validate token
		err = s.checkAuthorization(reqInfo.headerDetails.authorization, saasData, uaaData, TenantDeprovisioning)
		if err != nil {
			util.LogError(err, AuthorizationCheckFailed, TenantDeprovisioning, ca, nil)
			return &Result{Tenant: nil, Message: err.Error()}
		}
	}

	util.LogInfo("Tenant found", TenantDeprovisioning, ca, tenant)
	err = s.Clientset.SmeV1alpha1().CAPTenants(tenant.Namespace).Delete(context.TODO(), tenant.Name, metav1.DeleteOptions{})
	if err != nil {
		util.LogError(err, "Error deleting tenant", TenantDeprovisioning, ca, tenant)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	tenantIn := tenantInfo{tenantId: reqInfo.payload.tenantId, tenantSubDomain: reqInfo.payload.subdomain}
	callbackReqInfo := s.getCallbackReqInfo(reqInfo.subscriptionType, reqInfo.headerDetails.callbackInfo, saasData, smsData)
	s.initializeCallback(tenant.Name, ca, callbackReqInfo, reqInfo.subscriptionType, tenantIn, false)

	return &Result{Tenant: tenant, Message: ResourceDeleted}
}

func (s *SubscriptionHandler) checkCAPApp(globalAccountId string, btpAppName string) (*v1alpha1.CAPApplication, error) {
	labelSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, btpAppName),
	})
	if err != nil {
		return nil, err
	}

	capAppsList, err := s.Clientset.SmeV1alpha1().CAPApplications(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		return nil, err
	}
	if len(capAppsList.Items) == 0 {
		return nil, errors.New(ResourceNotFound)
	}
	// Assume only 1 app actually matches the selector!
	return &capAppsList.Items[0], nil
}

func (s *SubscriptionHandler) checkAuthorization(authHeader string, saasData *util.SaasRegistryCredentials, uaaData *util.XSUAACredentials, step string) error {
	if strings.Index(authHeader, BearerPrefix) != 0 {
		return errors.New("expected bearer token")
	}

	token := authHeader[7:]
	err := VerifyXSUAAJWTToken(context.TODO(), token, &XSUAAConfig{
		UAADomain:      saasData.UAADomain,
		ClientID:       saasData.ClientId,
		XSAppName:      uaaData.XSAppName,
		RequiredScopes: []string{uaaData.XSAppName + ".Callback", uaaData.XSAppName + ".mtcallback"},
	}, s.httpClientGenerator.NewHTTPClient())
	if err != nil {
		util.LogError(err, "failed token validation", step, "checkAuthorization", nil, "XSAppName", uaaData.XSAppName)
		return errors.New(AuthorizationCheckFailed)
	}
	return nil
}

func (s *SubscriptionHandler) checkCertIssuerAndSubject(xForwardedClientCert string, smsData *util.SmsCredentials, step string) error {
	if xForwardedClientCert == "" {
		err := errors.New("x-forwarded-client-cert header is empty")
		util.LogError(err, "certificate issuer and subject check failed", step, "checkCertIssuerAndSubject", nil)
		return err
	}

	// Decode PEM block
	decodedValue, err := url.QueryUnescape(xForwardedClientCert)
	if err != nil {
		util.LogError(err, "certificate issuer and subject check failed", step, "checkCertIssuerAndSubject", nil)
		return err
	}

	block, _ := pem.Decode([]byte(decodedValue))
	if block == nil {
		err := errors.New("failed to decode PEM block")
		util.LogError(err, "certificate issuer and subject check failed", step, "checkCertIssuerAndSubject", nil)
		return err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		util.LogError(err, "certificate issuer and subject check failed", step, "checkCertIssuerAndSubject", nil)
		return err
	}

	if s.checkCertificate(cert, smsData) != nil {
		util.LogError(err, "certificate check failed", step, "checkCertIssuerAndSubject", nil)
		return err
	}
	return nil
}

func (s *SubscriptionHandler) checkCertificate(cert *x509.Certificate, smsData *util.SmsCredentials) error {
	// check issuer
	var smsIssuerDNJson JsonDN
	err := json.Unmarshal([]byte(smsData.CallbackCertificateIssuer), &smsIssuerDNJson)
	if err != nil {
		return err
	}
	// Normalize both sides
	if !compareDN(normalizeX509(cert.Issuer), normalizeDNJson(smsIssuerDNJson)) {
		return fmt.Errorf("certificate issuer mismatch")
	}

	// check subject
	var smsSubjectDNJson JsonDN
	err = json.Unmarshal([]byte(smsData.CallbackCertificateSubject), &smsSubjectDNJson)
	if err != nil {
		return err
	}
	// Normalize both sides
	if !compareDN(normalizeX509(cert.Subject), normalizeDNJson(smsSubjectDNJson)) {
		return fmt.Errorf("certificate subject mismatch")
	}

	return nil
}

func (s *SubscriptionHandler) initializeCallback(tenantName string, ca *v1alpha1.CAPApplication, callbackReqInfo *util.CallbackReqInfo, subscriptionType subscriptionType, tenantIn tenantInfo, isProvisioning bool) {
	subscriptionDomain := ca.Annotations[AnnotationSubscriptionDomain]
	if subscriptionDomain == "" {
		subscriptionDomain = s.getPrimaryDomain(ca)
	}

	appUrl := "https://" + tenantIn.tenantSubDomain + "." + subscriptionDomain
	asyncCallbackPath := callbackReqInfo.CallbackPath
	util.LogInfo("Callback initialized", TenantProvisioning, ca, nil, "subscription URL", appUrl, "async callback path", asyncCallbackPath, "tenantName", tenantName)

	step := TenantProvisioning
	if !isProvisioning {
		step = TenantDeprovisioning
	}

	go func() {
		// create a context for tenant checks and outgoing requests
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Check tenant status asynchronously
		util.LogInfo("Starting tenant status check", step, ca, nil, "tenantName", tenantName)
		status := s.checkCAPTenantStatus(ctx, ca.Namespace, tenantName, isProvisioning, callbackReqInfo.CallbackTimeoutMillis)
		util.LogInfo("Tenant status check complete", step, ca, nil, "tenantName", tenantName, "status", status)

		additionalOutput := &map[string]any{}
		if isProvisioning {
			saasAdditionalOutput := ca.Annotations[AnnotationSaaSAdditionalOutput]
			if saasAdditionalOutput != "" {
				// Add additional output to the callback response
				err := json.Unmarshal([]byte(saasAdditionalOutput), additionalOutput)
				if err != nil {
					util.LogError(err, "Error parsing additional output", step, ca, nil, "annotation value", saasAdditionalOutput)
					additionalOutput = nil
				}
			}
			// Add tenant data to the additional output if it exists
			err := s.enrichAdditionalOutput(ca.Namespace, tenantIn.tenantId, additionalOutput)
			if err != nil {
				util.LogError(err, "Error updating tenant data", step, ca, nil, "tenantId", tenantIn.tenantId)
			}
		} else {
			additionalOutput = nil
		}
		s.handleAsyncCallback(ctx, callbackReqInfo, status, asyncCallbackPath, appUrl, additionalOutput, isProvisioning, subscriptionType)
	}()

	util.LogInfo("Waiting for async saas callback after checks...", step, ca, nil, "tenantName", tenantName)
}

func (s *SubscriptionHandler) getPrimaryDomain(ca *v1alpha1.CAPApplication) string {
	// If no domainRefs are specified, return an empty string
	if len(ca.Spec.DomainRefs) == 0 {
		return ""
	}
	// Return the first domain as the primary domain
	primaryDomainRef := ca.Spec.DomainRefs[0]
	domain := ""
	if primaryDomainRef.Kind == v1alpha1.DomainKind {
		primaryDom, err := s.Clientset.SmeV1alpha1().Domains(ca.Namespace).Get(context.TODO(), primaryDomainRef.Name, metav1.GetOptions{})
		if err != nil {
			util.LogError(err, "Error getting primary domain", TenantProvisioning, ca, nil, "domainRef", primaryDomainRef.Name)
		} else if primaryDom != nil {
			domain = primaryDom.Spec.Domain
		}
	} else {
		primaryDom, err := s.Clientset.SmeV1alpha1().ClusterDomains(metav1.NamespaceAll).Get(context.TODO(), primaryDomainRef.Name, metav1.GetOptions{})
		if err != nil {
			util.LogError(err, "Error getting primary cluster domain", TenantProvisioning, ca, nil, "domainRef", primaryDomainRef.Name)
		} else if primaryDom != nil {
			domain = primaryDom.Spec.Domain
		}
	}
	// Return the primary domain if it exists, else return an empty string
	return domain
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
		// Update relevant data from each CAPTenantOutput to saas callback additional output
		tenantDataOutput := &map[string]any{}
		err = json.Unmarshal([]byte(tenantData.Spec.SubscriptionCallbackData), tenantDataOutput)
		if err != nil {
			return err
		}
		// merge tenant data output into additional output
		for k, v := range *tenantDataOutput {
			(*additionalOutput)[k] = v
		}
	}
	return nil
}

func (s *SubscriptionHandler) checkCAPTenantStatus(ctx context.Context, tenantNamespace string, tenantName string, provisioning bool, callbackTimeoutMs string) bool {
	asyncCallbackTimeout := 15 * time.Minute
	if callbackTimeoutMs != "" {
		asyncCallbackTimeout, _ = time.ParseDuration(callbackTimeoutMs + "ms")
	}

	step := TenantProvisioning
	if !provisioning {
		step = TenantDeprovisioning
	}

	timedCtx, cancel := context.WithTimeout(ctx, asyncCallbackTimeout) // Assume tenants won't take over 15mins to be "Ready"
	defer cancel()

	for {
		select {
		case <-timedCtx.Done():
			klog.Warningf("tenant status check: %s", timedCtx.Err().Error())
			return false
		default:
			capTenant, err := s.Clientset.SmeV1alpha1().CAPTenants(tenantNamespace).Get(context.TODO(), tenantName, metav1.GetOptions{})
			if k8sErrors.IsNotFound(err) {
				util.LogInfo("No tenant found.. Exiting CAPTenant status check.", step, "Tenant Status Check", nil, "tenantName", tenantName, "namespace", tenantNamespace)
				if !provisioning {
					return true
				}
			}
			if capTenant != nil {
				util.LogInfo("CAPTenant found", step, capTenant, nil, "tenantid", capTenant.Spec.TenantId, "status", capTenant.Status.State)
				if provisioning && (capTenant.Status.State == v1alpha1.CAPTenantStateReady || capTenant.Status.State == v1alpha1.CAPTenantStateProvisioningError) {
					util.LogInfo("Exiting CAPTenant status check", step, capTenant, nil, "tenantid", capTenant.Spec.TenantId, "status", capTenant.Status.State)
					return capTenant.Status.State == v1alpha1.CAPTenantStateReady
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (s *SubscriptionHandler) getServiceDetails(ca *v1alpha1.CAPApplication, step string) (*util.SaasRegistryCredentials, *util.XSUAACredentials) {
	var (
		wg       sync.WaitGroup
		saasData *util.SaasRegistryCredentials
		uaaData  *util.XSUAACredentials
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		saasData = s.getSaasDetails(ca, step)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		uaaData = s.getXSUAADetails(ca, step)
	}()

	wg.Wait()
	return saasData, uaaData
}

func (s *SubscriptionHandler) getSaasDetails(capApp *v1alpha1.CAPApplication, step string) *util.SaasRegistryCredentials {
	var (
		result *util.SaasRegistryCredentials = nil
		err    error
		info   *v1alpha1.ServiceInfo
	)
	if info, err = s.getServiceInfo(capApp, "saas-registry"); err == nil {
		result, err = util.ReadServiceCredentialsFromSecret[util.SaasRegistryCredentials](info, capApp.Namespace, s.KubeClienset)
	}
	if err != nil {
		util.LogError(err, "SaaS Registry credentials could not be read. Exiting..", step, capApp, nil)
	}
	return result
}

func (s *SubscriptionHandler) getXSUAADetails(capApp *v1alpha1.CAPApplication, step string) *util.XSUAACredentials {
	var (
		result *util.XSUAACredentials = nil
		err    error
		info   *v1alpha1.ServiceInfo
	)
	info = util.GetXSUAAInfo(capApp.Spec.BTP.Services, capApp)

	if info == nil {
		err = fmt.Errorf("could not find service with class %s in CAPApplication %s.%s", "xsuaa", capApp.Namespace, capApp.Name)
	} else {
		result, err = util.ReadServiceCredentialsFromSecret[util.XSUAACredentials](info, capApp.Namespace, s.KubeClienset)
	}

	if err != nil {
		util.LogError(err, "XSUAA credentials could not be read. Exiting..", step, capApp, nil)
	}
	return result
}

func (s *SubscriptionHandler) getSmsDetails(capApp *v1alpha1.CAPApplication, step string) *util.SmsCredentials {
	var (
		result *util.SmsCredentials = nil
		err    error
		info   *v1alpha1.ServiceInfo
	)
	if info, err = s.getServiceInfo(capApp, "subscription-manager"); err == nil {
		result, err = util.ReadServiceCredentialsFromSecret[util.SmsCredentials](info, capApp.Namespace, s.KubeClienset)
	}
	if err != nil {
		util.LogError(err, "SaaS Registry credentials could not be read. Exiting..", step, capApp, nil)
	}
	return result
}

func (s *SubscriptionHandler) getServiceInfo(ca *v1alpha1.CAPApplication, serviceClass string) (*v1alpha1.ServiceInfo, error) {
	for i := range ca.Spec.BTP.Services {
		if ca.Spec.BTP.Services[i].Class == serviceClass {
			return &ca.Spec.BTP.Services[i], nil
		}
	}
	return nil, fmt.Errorf("could not find service with class %s in CAPApplication %s.%s", serviceClass, ca.Namespace, ca.Name)
}

func prepareTokenRequest(ctx context.Context, callbackReqInfo *util.CallbackReqInfo, client *http.Client) (tokenReq *http.Request, err error) {
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
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if callbackReqInfo.CredentialType != "x509" {
		tokenReq.Header.Set("Authorization", BasicPrefix+base64.StdEncoding.EncodeToString([]byte(callbackReqInfo.ClientId+":"+callbackReqInfo.ClientSecret)))
	}

	return tokenReq, nil
}

func (s *SubscriptionHandler) handleAsyncCallback(ctx context.Context, callbackReqInfo *util.CallbackReqInfo, status bool, asyncCallbackPath string, appUrl string, additionalOutput *map[string]any, isProvisioning bool, subscriptionType subscriptionType) {
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
	} else {
		klog.V(2).InfoS("Obtained token for async callback", "response", tokenResponse)
		// Get the relevant OAuth request
		decoder := json.NewDecoder(tokenResponse.Body)
		var oAuthType OAuthResponse
		err := decoder.Decode(&oAuthType)
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
		switch subscriptionType {
		case SMS:
			payload, _ = json.Marshal(&SmsCallbackResponse{
				Status:           checkMatch(status, CallbackSucceeded, CallbackFailed),
				Message:          checkMatch(status, checkMatch(isProvisioning, ProvisioningSucceededMessage, DeprovisioningSucceededMessage), checkMatch(isProvisioning, ProvisioningFailedMessage, DeprovisioningFailedMessage)),
				ApplicationUrl:   appUrl,
				AdditionalOutput: additionalOutput,
			})
		default:
			payload, _ = json.Marshal(&SaaSCallbackResponse{
				Status:           checkMatch(status, CallbackSucceeded, CallbackFailed),
				Message:          checkMatch(status, checkMatch(isProvisioning, ProvisioningSucceededMessage, DeprovisioningSucceededMessage), checkMatch(isProvisioning, ProvisioningFailedMessage, DeprovisioningFailedMessage)),
				SubscriptionUrl:  appUrl,
				AdditionalOutput: additionalOutput,
			})
		}

		callbackReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, callbackReqInfo.CallbackUrl+asyncCallbackPath, bytes.NewBuffer(payload))
		callbackReq.Header.Set("Content-Type", "application/json")
		callbackReq.Header.Set("Authorization", BearerPrefix+oAuthType.AccessToken)

		client := s.httpClientGenerator.NewHTTPClient()
		klog.V(2).InfoS("Triggering callback", "request", callbackReq)

		callbackResponse, err := client.Do(callbackReq)
		if err != nil {
			klog.ErrorS(err, "Error sending async callback")
			return
		} else {
			klog.InfoS("Async callback done", "response", callbackResponse.Body, "status", callbackResponse.Status)
			defer callbackResponse.Body.Close()
		}
	}

	klog.InfoS("Exiting from async callback..")
}

func (s *SubscriptionHandler) HandleRequest(w http.ResponseWriter, req *http.Request, subscriptionType subscriptionType) {
	var subscriptionResult *Result
	var reqInfo *RequestInfo
	// Response
	defer func() {
		subscriptionResult.Tenant = nil // Don't return tenant details in response
		res, _ := json.Marshal(subscriptionResult)
		w.Write(res)
	}()

	switch req.Method {
	case http.MethodPut:
		defer func() {
			if reqInfo != nil {
				subscriptionResult = s.CreateTenant(reqInfo)
				if subscriptionResult.Tenant == nil {
					w.WriteHeader(http.StatusNotAcceptable)
				} else {
					w.WriteHeader(http.StatusAccepted)
				}
			}
		}()
	case http.MethodDelete:
		defer func() {
			if reqInfo != nil {
				subscriptionResult = s.DeleteTenant(reqInfo)
				if subscriptionResult.Message == TenantNotFound {
					w.WriteHeader(http.StatusNotFound)
				} else if subscriptionResult.Message != ResourceDeleted {
					w.WriteHeader(http.StatusNotAcceptable)
				} else {
					w.WriteHeader(http.StatusAccepted)
				}
			}
		}()
	default:
		subscriptionResult = &Result{Tenant: nil, Message: InvalidRequestMethod}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	// Decode the request to get tenant details
	reqInfo, err := DecodeRequest(req, subscriptionType)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		subscriptionResult = &Result{Tenant: nil, Message: err.Error()}
	}
}

func (s *SubscriptionHandler) HandleSaaSRequest(w http.ResponseWriter, req *http.Request) {
	s.HandleRequest(w, req, SaaS)
}

func (s *SubscriptionHandler) HandleSMSRequest(w http.ResponseWriter, req *http.Request) {
	s.HandleRequest(w, req, SMS)
}

func DecodeRequest(req *http.Request, subscriptionType subscriptionType) (*RequestInfo, error) {
	var subscriptionGUID, tenantId, subdomain, globalAccountId, appName, commercialAppName string
	var jsonPayload map[string]any

	if !(req.Method == http.MethodDelete && subscriptionType == SMS) {
		decoder := json.NewDecoder(req.Body)
		err := decoder.Decode(&jsonPayload)
		if err != nil {
			return nil, fmt.Errorf("error decoding request: %w", err)
		}
	}

	var hdrDetails headerDetails
	switch subscriptionType {
	case SMS:
		hdrDetails.callbackInfo = req.Header.Get("Status_callback")
		hdrDetails.xForwardedClientCert = req.Header.Get("X-Forwarded-Client-Cert")

		switch req.Method {
		case http.MethodPut:
			subscriber := jsonPayload["subscriber"].(map[string]any)
			subscriptionGUID = subscriber["subscriptionGUID"].(string)
			tenantId = subscriber["app_tid"].(string)
			subdomain = subscriber["subaccountSubdomain"].(string)
			globalAccountId = subscriber["globalAccountId"].(string)
			rootApp := jsonPayload["rootApplication"].(map[string]any)
			appName = rootApp["appName"].(string)
			commercialAppName = rootApp["commercialAppName"].(string)
		case http.MethodDelete:
			// get paramater from URL
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
		hdrDetails.authorization = req.Header.Get("Authorization")
		hdrDetails.callbackInfo = req.Header.Get("STATUS_CALLBACK")

		subscriptionGUID = jsonPayload["subscriptionGUID"].(string)
		tenantId = jsonPayload["subscribedTenantId"].(string)
		subdomain = jsonPayload["subscribedSubdomain"].(string)
		globalAccountId = jsonPayload["globalAccountGUID"].(string)
		appName = jsonPayload["subscriptionAppName"].(string)
		commercialAppName = jsonPayload["subscriptionCommercialAppName"].(string)
	}

	payload := &payloadDetails{
		// GTID
		subscriptionGUID:  subscriptionGUID,
		tenantId:          tenantId,
		subdomain:         subdomain,
		globalAccountId:   globalAccountId,
		appName:           appName,
		commercialAppName: commercialAppName,
		raw:               &jsonPayload,
	}
	return &RequestInfo{
		subscriptionType: subscriptionType,
		payload:          payload,
		headerDetails:    &hdrDetails,
	}, nil
}

func NewSubscriptionHandler(clientset versioned.Interface, kubeClienset kubernetes.Interface) *SubscriptionHandler {
	return &SubscriptionHandler{Clientset: clientset, KubeClienset: kubeClienset, httpClientGenerator: &httpClientGeneratorImpl{}}
}

// Returns an sha1 checksum for a given source string
func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}
