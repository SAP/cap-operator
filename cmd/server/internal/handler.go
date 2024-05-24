/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
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
)

const (
	LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"
	LabelTenantId                     = "sme.sap.com/btp-tenant-id"
)

const (
	ResourceCreated  = "resource created successfully"
	ResourceFound    = "resource exists"
	ResourceDeleted  = "resource deleted successfully"
	ResourceNotFound = "resource not found"
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

type Result struct {
	Tenant  *v1alpha1.CAPTenant
	Message string
}

type SubscriptionHandler struct {
	Clientset           versioned.Interface
	KubeClienset        kubernetes.Interface
	httpClientGenerator httpClientGenerator
}

type CallbackResponse struct {
	Status           string          `json:"status"`
	Message          string          `json:"message"`
	SubscriptionUrl  string          `json:"subscriptionUrl"`
	AdditionalOutput *map[string]any `json:"additionalOutput,omitempty"`
}
type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

func (s *SubscriptionHandler) CreateTenant(req *http.Request) *Result {
	klog.InfoS("Create Tenant triggered")
	var created = false
	// Get the relevant provisioning request
	decoder := json.NewDecoder(req.Body)
	var reqType map[string]any
	err := decoder.Decode(&reqType)
	if err != nil {
		klog.ErrorS(err, ErrorOccurred)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	// Check if CAPApplication instance for the given btpApp exists
	ca, err := s.checkCAPApp(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string))
	if err != nil {
		klog.ErrorS(err, ErrorOccurred)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	// fetch SaaS Registry and XSUAA information
	saasData, uaaData := s.getServiceDetails(ca)
	if saasData == nil || uaaData == nil {
		return &Result{Tenant: nil, Message: ResourceNotFound}
	}

	// validate token
	err = s.checkAuthorization(req.Header.Get("Authorization"), saasData, uaaData)
	if err != nil {
		return &Result{Tenant: nil, Message: err.Error()}
	}

	// Check if A CRO for CAPTenant already exists
	tenant := s.getTenant(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string), reqType["subscribedTenantId"].(string), ca.Namespace).Tenant

	// If the resource doesn't exist, we'll create it
	if tenant == nil {
		created = true
		jsonReqByte, _ := json.Marshal(reqType)
		// Create a secret to store the subscription context (payload from the request)
		secret, err := s.KubeClienset.CoreV1().Secrets(ca.Namespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: ca.Name + "-consumer-",
				Namespace:    ca.Namespace,
				Labels: map[string]string{
					LabelBTPApplicationIdentifierHash: sha1Sum(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string)),
					LabelTenantId:                     reqType["subscribedTenantId"].(string),
				},
			},
			StringData: map[string]string{
				"subscriptionContext": string(jsonReqByte),
			},
		}, metav1.CreateOptions{})
		if err != nil {
			// Log error and exit if secret creation fails
			klog.ErrorS(err, "Error creating secret")
			return &Result{Tenant: nil, Message: err.Error()}
		}

		klog.InfoS("Creating tenant", "caName", ca.Name, "namespace", ca.Namespace, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
		tenant, _ = s.Clientset.SmeV1alpha1().CAPTenants(ca.Namespace).Create(context.TODO(), &v1alpha1.CAPTenant{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: ca.Name + "-",
				Namespace:    ca.Namespace,
				Annotations: map[string]string{
					AnnotationSubscriptionContextSecret: secret.Name, // Store the secret name in the tenant annotation
				},
				Labels: map[string]string{
					LabelBTPApplicationIdentifierHash: sha1Sum(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string)),
					LabelTenantId:                     reqType["subscribedTenantId"].(string),
				},
			},
			Spec: v1alpha1.CAPTenantSpec{
				CAPApplicationInstance: ca.Name,
				BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
					SubDomain: reqType["subscribedSubdomain"].(string),
					TenantId:  reqType["subscribedTenantId"].(string),
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
		s.initializeCallback(tenant.Name, ca, saasData, req, reqType["subscribedSubdomain"].(string), true)
	}

	// Tenant created/exists
	message := func(isCreated bool) string {
		if isCreated {
			return ResourceCreated
		} else {
			return ResourceFound
		}
	}
	klog.V(2).InfoS("Tenant successfully created", "message", message(created), "tenant", tenant, "caName", ca.Name, "namespace", ca.Namespace, "tenant", tenant, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
	return &Result{Tenant: tenant, Message: message(created)}
}

func (s *SubscriptionHandler) updateSecret(tenant *v1alpha1.CAPTenant, secret *corev1.Secret) error {
	if tenant != nil {
		secret.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(tenant, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPTenantKind)),
		}
		_, err := s.KubeClienset.CoreV1().Secrets(tenant.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Error updating payload tenant subscription secret")
			return err
		}
	}
	return nil
}

func (s *SubscriptionHandler) getTenant(globalAccountGUID string, btpAppName string, tenantId string, namespace string) *Result {
	labelSelector, err := labels.ValidatedSelectorFromSet(map[string]string{
		LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountGUID, btpAppName),
		LabelTenantId:                     tenantId,
	})
	if err != nil {
		klog.ErrorS(err, "Error occurred in getTenant", "namespace", namespace, "tenantId", tenantId, LabelBTPApplicationIdentifierHash, sha1Sum(globalAccountGUID, btpAppName))
		return &Result{Tenant: nil, Message: err.Error()}
	}

	ctList, err := s.Clientset.SmeV1alpha1().CAPTenants(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil {
		klog.ErrorS(err, "Error occurred in getTenant", "namespace", namespace, "tenantId", tenantId, LabelBTPApplicationIdentifierHash, sha1Sum(globalAccountGUID, btpAppName))
		return &Result{Tenant: nil, Message: err.Error()}
	}
	if len(ctList.Items) == 0 {
		klog.InfoS("No tenant found", "namespace", namespace, "tenantId", tenantId, LabelBTPApplicationIdentifierHash, sha1Sum(globalAccountGUID, btpAppName))
		return &Result{Tenant: nil, Message: ResourceNotFound}
	}
	// Assume only 1 tenant actually matches the selector!
	klog.V(2).InfoS("Tenant found", v1alpha1.CAPApplicationKind, &ctList.Items[0], "namespace", namespace, "tenantId", tenantId, LabelBTPApplicationIdentifierHash, sha1Sum(globalAccountGUID, btpAppName))
	return &Result{Tenant: &ctList.Items[0], Message: ResourceFound}
}

func (s *SubscriptionHandler) DeleteTenant(req *http.Request) *Result {
	klog.InfoS("Delete Tenant triggered")
	// Get the relevant deprovisioning request
	decoder := json.NewDecoder(req.Body)
	var reqType map[string]interface{}
	err := decoder.Decode(&reqType)
	if err != nil {
		klog.ErrorS(err, ErrorOccurred)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	// Check if CAPApplication instance for the given btpApp exists
	ca, err := s.checkCAPApp(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string))
	if err != nil {
		klog.ErrorS(err, ErrorOccurred)
		return &Result{Tenant: nil, Message: err.Error()}
	}

	// fetch SaaS Registry and XSUAA information
	saasData, uaaData := s.getServiceDetails(ca)
	if saasData == nil || uaaData == nil {
		return &Result{Tenant: nil, Message: ResourceNotFound}
	}

	// validate token
	err = s.checkAuthorization(req.Header.Get("Authorization"), saasData, uaaData)
	if err != nil {
		klog.ErrorS(err, "Error occurred in checkAuthorization", LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
		return &Result{Tenant: nil, Message: err.Error()}
	}

	tenant := s.getTenant(reqType["globalAccountGUID"].(string), reqType["subscriptionAppName"].(string), reqType["subscribedTenantId"].(string), ca.Namespace).Tenant

	tenantName := ResourceNotFound
	if tenant != nil {
		tenantName = tenant.Name
		klog.InfoS("Tenant found, deleting", "tenant", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
		err = s.Clientset.SmeV1alpha1().CAPTenants(tenant.Namespace).Delete(context.TODO(), tenant.Name, metav1.DeleteOptions{})
		if err != nil {
			klog.ErrorS(err, "Error deleting tenant", "tenant", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
			return &Result{Tenant: nil, Message: err.Error()}
		}
	}

	s.initializeCallback(tenantName, ca, saasData, req, reqType["subscribedSubdomain"].(string), false)

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

func (s *SubscriptionHandler) checkAuthorization(authHeader string, saasData *util.SaasRegistryCredentials, uaaData *util.XSUAACredentials) error {
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
		klog.ErrorS(err, "failed token validation", "XSAppName", uaaData.XSAppName)
		return errors.New(AuthorizationCheckFailed)
	}
	return nil
}

func (s *SubscriptionHandler) initializeCallback(tenantName string, ca *v1alpha1.CAPApplication, saasData *util.SaasRegistryCredentials, req *http.Request, tenantSubDomain string, isProvisioning bool) {
	appUrl := "https://" + tenantSubDomain + "." + ca.Spec.Domains.Primary
	asyncCallbackPath := req.Header.Get("STATUS_CALLBACK")
	klog.InfoS("callback initialized", "subscription URL", appUrl, "async callback path", asyncCallbackPath, "tenantId", ca.Spec.Provider.TenantId, "tenantName", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])

	go func() {
		// create a context for tenant checks and outgoing requests
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Check tenant status asynchronously
		klog.InfoS("Waiting for tenant status check...", "tenantId", ca.Spec.Provider.TenantId, "tenantName", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
		status := s.checkCAPTenantStatus(ctx, ca.Namespace, tenantName, isProvisioning, saasData.CallbackTimeoutMillis)
		klog.InfoS("CAPTenant check complete", "status", status, "tenantId", ca.Spec.Provider.TenantId, "tenantName", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])

		additionalOutput := &map[string]any{}
		if isProvisioning {
			saasAdditionalOutput := ca.Annotations[AnnotationSaaSAdditionalOutput]
			if saasAdditionalOutput != "" {
				// Add additional output to the callback response
				err := json.Unmarshal([]byte(saasAdditionalOutput), additionalOutput)
				if err != nil {
					klog.ErrorS(err, "Error parsing additional output", "annotation value", saasAdditionalOutput)
					additionalOutput = nil
				}
			}
		} else {
			additionalOutput = nil
		}
		s.handleAsyncCallback(ctx, saasData, status, asyncCallbackPath, appUrl, additionalOutput, isProvisioning)
	}()

	klog.InfoS("Waiting for async saas callback after checks...", "tenantId", ca.Spec.Provider.TenantId, "tenantName", tenantName, LabelBTPApplicationIdentifierHash, ca.Labels[LabelBTPApplicationIdentifierHash])
}

func (s *SubscriptionHandler) checkCAPTenantStatus(ctx context.Context, tenantNamespace string, tenantName string, provisioning bool, callbackTimeoutMs string) bool {
	asyncCallbackTimeout := 15 * time.Minute
	if callbackTimeoutMs != "" {
		asyncCallbackTimeout, _ = time.ParseDuration(callbackTimeoutMs + "ms")
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
				klog.InfoS("No tenant found.. Exiting CAPTenant status check.", "tenantName", tenantName, "namespace", tenantNamespace)
				if !provisioning {
					return true
				}
			}
			if capTenant != nil {
				klog.InfoS("CAPTenant Found", "tenantid", capTenant.Spec.TenantId, "status", capTenant.Status.State, LabelBTPApplicationIdentifierHash, capTenant.Labels[LabelBTPApplicationIdentifierHash])
				if provisioning && (capTenant.Status.State == v1alpha1.CAPTenantStateReady || capTenant.Status.State == v1alpha1.CAPTenantStateProvisioningError) {
					klog.InfoS("Exiting CAPTenant status check", "tenantid", capTenant.Spec.TenantId, "result status", capTenant.Status.State, LabelBTPApplicationIdentifierHash, capTenant.Labels[LabelBTPApplicationIdentifierHash])
					return capTenant.Status.State == v1alpha1.CAPTenantStateReady
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (s *SubscriptionHandler) getServiceDetails(ca *v1alpha1.CAPApplication) (*util.SaasRegistryCredentials, *util.XSUAACredentials) {
	var (
		wg       sync.WaitGroup
		saasData *util.SaasRegistryCredentials
		uaaData  *util.XSUAACredentials
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		saasData = s.getSaasDetails(ca)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		uaaData = s.getXSUAADetails(ca)
	}()

	wg.Wait()
	return saasData, uaaData
}

func (s *SubscriptionHandler) getSaasDetails(capApp *v1alpha1.CAPApplication) *util.SaasRegistryCredentials {
	var (
		result *util.SaasRegistryCredentials = nil
		err    error
		info   *v1alpha1.ServiceInfo
	)
	if info, err = s.getServiceInfo(capApp, "saas-registry"); err == nil {
		result, err = util.ReadServiceCredentialsFromSecret[util.SaasRegistryCredentials](info, capApp.Namespace, s.KubeClienset)
	}
	if err != nil {
		klog.ErrorS(err, "SaaS Registry credentials could not be read. Exiting..", "tenantId", capApp.Spec.Provider.TenantId, LabelBTPApplicationIdentifierHash, capApp.Labels[LabelBTPApplicationIdentifierHash])
	}
	return result
}

func (s *SubscriptionHandler) getXSUAADetails(capApp *v1alpha1.CAPApplication) *util.XSUAACredentials {
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
		klog.ErrorS(err, "XSUAA credentials could not be read. Exiting..", LabelBTPApplicationIdentifierHash, capApp.Labels[LabelBTPApplicationIdentifierHash])
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

func prepareTokenRequest(ctx context.Context, saasData *util.SaasRegistryCredentials, client *http.Client) (tokenReq *http.Request, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error preparing token request: %w", err)
		}
	}()
	var (
		tokenURL string
	)
	if saasData.CredentialType == "x509" {
		tokenURL = saasData.CertificateUrl + "/oauth/token"

		// setup client for mTLS
		cert, err := tls.X509KeyPair([]byte(saasData.Certificate), []byte(saasData.CertificateKey))
		if err != nil {
			return nil, err
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM([]byte(saasData.Certificate))
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
		tokenURL = saasData.AuthUrl + "/oauth/token"
	}
	tokenData := url.Values{}
	tokenData.Add("client_id", saasData.ClientId)
	tokenData.Add("grant_type", "client_credentials")

	tokenReq, err = http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if saasData.CredentialType != "x509" {
		tokenReq.Header.Set("Authorization", BasicPrefix+base64.StdEncoding.EncodeToString([]byte(saasData.ClientId+":"+saasData.ClientSecret)))
	}

	return tokenReq, nil
}

func (s *SubscriptionHandler) handleAsyncCallback(ctx context.Context, saasData *util.SaasRegistryCredentials, status bool, asyncCallbackPath string, appUrl string, additionalOutput *map[string]any, isProvisioning bool) {
	// Get OAuth token
	tokenClient := s.httpClientGenerator.NewHTTPClient()
	tokenReq, err := prepareTokenRequest(ctx, saasData, tokenClient)
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

		payload, _ := json.Marshal(&CallbackResponse{
			Status:           checkMatch(status, CallbackSucceeded, CallbackFailed),
			Message:          checkMatch(status, checkMatch(isProvisioning, ProvisioningSucceededMessage, DeprovisioningSucceededMessage), checkMatch(isProvisioning, ProvisioningFailedMessage, DeprovisioningFailedMessage)),
			SubscriptionUrl:  appUrl,
			AdditionalOutput: additionalOutput,
		})
		callbackReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, saasData.SaasManagerUrl+asyncCallbackPath, bytes.NewBuffer(payload))
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

func (s *SubscriptionHandler) HandleRequest(w http.ResponseWriter, req *http.Request) {
	var subscriptionResult *Result
	switch req.Method {
	case http.MethodPut:
		subscriptionResult = s.CreateTenant(req)
		if subscriptionResult.Tenant == nil {
			w.WriteHeader(http.StatusNotAcceptable)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	case http.MethodDelete:
		subscriptionResult = s.DeleteTenant(req)
		if subscriptionResult.Message != ResourceDeleted {
			w.WriteHeader(http.StatusNotAcceptable)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	default:
		subscriptionResult = &Result{Tenant: nil, Message: InvalidRequestMethod}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	subscriptionResult.Tenant = nil // Don't return tenant details in response
	res, _ := json.Marshal(subscriptionResult)
	w.Write(res)
}

func NewSubscriptionHandler(clientset versioned.Interface, kubeClienset kubernetes.Interface) *SubscriptionHandler {
	return &SubscriptionHandler{Clientset: clientset, KubeClienset: kubeClienset, httpClientGenerator: &httpClientGeneratorImpl{}}
}

// Returns an sha1 checksum for a given source string
func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}
