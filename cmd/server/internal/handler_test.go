/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
)

const RequestPath = "/provision"
const SmsRequestPath = "/sms/provision/tenants"

type httpTestClientGenerator struct {
	client *http.Client
}

func (facade *httpTestClientGenerator) NewHTTPClient() *http.Client { return facade.client }

const (
	providerName         = "ca-test-controller"
	subName              = providerName + "-subscription"
	appName              = "some-app-name"
	globalAccountId      = "cap-app-global"
	providerSubaccountId = "012012012-1234-1234-123456012345"
	subDomain            = "foo"
	tenantId             = "012012012-1234-1234-123456"
	subscriptionGUID     = "012301234-2345-6789-ABCDEF"
)

// dependenciesJSON is the precomputed dependency payload published by the controller to SubscriptionProvider.Status.Dependencies
const dependenciesJSON = `[{"xsappname":"saasappname!b15"},{"xsappname":"smappname!b15"},{"appId":"destappname!b15","appName":"destination"},{"xsappname":"rtappname!b15"}]`

func setup(client *http.Client, secrets []runtime.Object, objects ...runtime.Object) *SubscriptionHandler {
	subHandler := NewSubscriptionHandler(fake.NewSimpleClientset(objects...), k8sfake.NewSimpleClientset(secrets...))
	if client != nil {
		subHandler.httpClientGenerator = &httpTestClientGenerator{client: client}
	}
	return subHandler
}

func createSecrets() []runtime.Object {
	secs := []runtime.Object{}
	secs = append(secs, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-xsuaa-sec",
			Namespace: v1.NamespaceDefault,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"credentials": []byte(`{
				"uaadomain": "auth.service.local",
				"xsappname": "appname!b14",
				"trustedclientidsuffix": "|appname!b14",
				"verificationkey": "",
				"sburl": "internal.auth.service.local",
				"url": "https://app-domain.auth.service.local",
				"credential-type": "instance-secret"
			}`),
		},
	}, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-saas-sec",
			Namespace: v1.NamespaceDefault,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"credentials": []byte(`{
				"appUrls": "{\"getDependencies\":\"https://appSubdomain.appname.clusterdomain.com/callback/v1.0/dependencies\",\"onSubscription\":\"https://cap-op.clusterdomain.com/provision/tenants/{tenantId}\",\"getSubscriptionParameters\":\"\",\"onSubscriptionAsync\":true,\"onUnSubscriptionAsync\":true,\"onUpdateSubscriptionParametersAsync\":false,\"callbackTimeoutMillis\":300000,\"runGetDependenciesOnAsyncCallback\":false,\"onUpdateDependenciesAsync\":false}",
				"saas_registry_url": "https://sm.service.local",
				"clientid": "clientid",
				"clientsecret": "clientsecret",
				"uaadomain": "auth.service.local",
				"sburl": "internal.auth.service.local",
				"url": "https://app-domain.auth.service.local",
				"saasregistryenabled": true,
				"uaa": {"xsappname": "saasappname!b15" },
				"credential-type": "instance-secret"
			}`),
		},
	})

	return secs
}

func createSmsSecret() []runtime.Object {
	secs := []runtime.Object{}
	secs = append(secs, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-sms-sec",
			Namespace: v1.NamespaceDefault,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"credentials": []byte(`{
				"app_urls": "{\"subscriptionCallbacks\":{\"url\":\"https://cap-op.clusterdomain.com/provision/tenants/{app_tid}\",\"async\":{\"updateDependenciesEnable\":false,\"updateSubscriptionParametersEnable\":false,\"subscribeEnable\":true,\"unSubscribeEnable\":true,\"timeoutInMillis\":300000}},\"omitSubscriptionCallbacks\":null,\"dependenciesCallbacks\":{\"url\":\"https://appSubdomain.appname.clusterdomain.com/v1.0/callback/tenants/{app_tid}/dependencies\"},\"subscriptionParamsCallbacks\":{\"url\":\"\"}}",
				"callback_certificate_issuer": "{\"C\":\"DE\",\"L\":\"*\",\"O\":\"RandomOrg\",\"OU\":\"RandomOrgUnit\",\"CN\":\"*.auth.service.local\"}",
    			"callback_certificate_subject": "{\"CN\":\"*.auth.service.local\",\"L\":\"RandomCity\",\"OU\": [\"RandomOrgUnit\"],\"O\":\"RandomOrg\",\"C\":\"DE\"}",
    			"callback_certificate_subject_rfc_2253": "CN=*.auth.service.local,L=RandomCity,OU=RandomOrgUnit,O=RandomOrg,C=DE",
				"category": "CAP",
				"clientid": "clientid",
				"clientsecret": "clientsecret",
				"credential-type": "binding-secret",
				"sburl": "internal.auth.service.local",
				"url": "https://app-domain.auth.service.local",
				"uaadomain": "auth.service.local"
			}`),
		},
	})

	return secs
}

// createSubscriptionProvider builds the SubscriptionProvider fixture that the handler now resolves for auth + dependencies.
func createSubscriptionProvider(subType subscriptionType) *v1alpha2.SubscriptionProvider {
	info := v1alpha2.SubscriptionInfo{}
	if subType == SMS {
		info.Type = "subscription-manager"
		info.SubscriptionSecret = "test-sms-sec"
	} else {
		info.Type = "saas-registry"
		info.SubscriptionSecret = "test-saas-sec"
		info.AuthSecret = "test-xsuaa-sec"
	}
	return &v1alpha2.SubscriptionProvider{
		ObjectMeta: v1.ObjectMeta{
			Name:      providerName,
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelAppIdHash: sha1Sum(providerSubaccountId, appName),
			},
		},
		Spec: v1alpha2.SubscriptionProviderSpec{
			AppName:              appName,
			ProviderSubaccountID: providerSubaccountId,
			SubscriptionInfo:     info,
			Dependencies:         dependenciesJSON,
		},
	}
}

// createSubscription builds an existing Subscription fixture correlated to the provider via app-identifier + tenant labels.
func createSubscription(state v1alpha2.SubscriptionState, guid string) *v1alpha2.Subscription {
	sub := &v1alpha2.Subscription{
		ObjectMeta: v1.ObjectMeta{
			Name:      subName,
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelAppIdHash:           sha1Sum(providerSubaccountId, appName),
				LabelTenantId:            tenantId,
				MetadataSubscriptionGUID: guid,
			},
		},
		Spec: v1alpha2.SubscriptionSpec{
			AppName:              appName,
			ProviderSubaccountId: providerSubaccountId,
			TenantId:             tenantId,
			Subdomain:            subDomain,
			SubscriptionGuid:     guid,
		},
	}
	if state != "" {
		sub.Status.State = state
	}
	return sub
}

func TestMain(m *testing.M) {
	m.Run()
}

func Test_IncorrectMethod(t *testing.T) {
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, RequestPath, strings.NewReader(`{"subscriptionAppName":"`+appName+`","globalAccountGUID":"`+globalAccountId+`","subscriptionGUID":"`+subscriptionGUID+`","subscribedTenantId":"`+tenantId+`","subscribedSubdomain":"`+subDomain+`"}`))
	subHandler := setup(nil, createSecrets())
	subHandler.HandleSaaSRequest(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status '%d', received '%d'", http.StatusMethodNotAllowed, res.Code)
	}

	// Get the relevant response
	decoder := json.NewDecoder(res.Body)
	var resType Result
	err := decoder.Decode(&resType)
	if err != nil {
		t.Error("Unexpected error in expected response: ", res.Body)
	}

	if resType.Subscription != nil && resType.Message != InvalidRequestMethod {
		t.Error("Response: ", res.Body, " does not match expected result: ", InvalidRequestMethod)
	}

}

func Test_provisioning(t *testing.T) {
	tests := []struct {
		name                  string
		method                string
		body                  string
		createCROs            bool
		withAdditionalData    bool
		invalidAdditionalData bool
		existingSubscription  bool
		existingTenantOutput  bool
		expectedStatusCode    int
		expectedResponse      Result
	}{
		{
			name:               "Invalid Provisioning Request",
			method:             http.MethodPut,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF",
			},
		},
		{
			name:               "Provisioning Request without CROs",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: ResourceNotFound,
			},
		},
		{
			name:               "Provisioning Request with CROs with invalid app name",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"test-app","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: ResourceNotFound,
			},
		},
		{
			name:               "Provisioning Request valid",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid with additional data and existing subscription",
			method:               http.MethodPut,
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:           true,
			withAdditionalData:   true,
			existingSubscription: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceUpdated,
			},
		},
		{
			name:                 "Provisioning Request valid with additional data and existing subscription and existing tenant output",
			method:               http.MethodPut,
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:           true,
			withAdditionalData:   true,
			existingSubscription: true,
			existingTenantOutput: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceUpdated,
			},
		},
		{
			name:                  "Provisioning Request valid with invalid additional data and existing subscription",
			method:                http.MethodPut,
			body:                  `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:            true,
			withAdditionalData:    true,
			invalidAdditionalData: true,
			existingSubscription:  true,
			expectedStatusCode:    http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceUpdated,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				subPro := createSubscriptionProvider(SaaS)
				if testData.withAdditionalData {
					if !testData.invalidAdditionalData {
						subPro.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{\"foo\":\"bar\"}"}
					} else {
						subPro.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{foo\":\"bar\"}"} //invalid json
					}
				}
				runtimeObjs = append(runtimeObjs, subPro)
			}
			if testData.existingSubscription {
				runtimeObjs = append(runtimeObjs, createSubscription("", subscriptionGUID))
			}
			if testData.existingTenantOutput {
				runtimeObjs = append(runtimeObjs, &v1alpha2.CAPTenantOutput{ObjectMeta: v1.ObjectMeta{Name: subName, Namespace: v1.NamespaceDefault, Labels: map[string]string{LabelTenantId: tenantId}}, Spec: v1alpha2.CAPTenantOutputSpec{SubscriptionCallbackData: "{\"foo3\":\"bar3\"}"}})
			}

			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			subHandler := setup(client, createSecrets(), runtimeObjs...)

			res := httptest.NewRecorder()
			req := httptest.NewRequest(testData.method, RequestPath, strings.NewReader(testData.body))
			req.Header.Set("Authorization", "Bearer "+tokenString)
			subHandler.HandleSaaSRequest(res, req)
			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			// Get the relevant response
			decoder := json.NewDecoder(res.Body)
			var resType Result
			err = decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.Subscription != testData.expectedResponse.Subscription && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func Test_sms_provisioning(t *testing.T) {
	tests := []struct {
		name                  string
		method                string
		body                  string
		createCROs            bool
		withAdditionalData    bool
		invalidAdditionalData bool
		existingSubscription  bool
		existingTenantOutput  bool
		expectedStatusCode    int
		expectedResponse      Result
	}{
		{
			name:               "Invalid Provisioning Request",
			method:             http.MethodPut,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF",
			},
		},
		{
			name:               "Provisioning Request without CROs",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","providerSubaccountId":"` + providerSubaccountId + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: ResourceNotFound,
			},
		},
		{
			name:               "Provisioning Request with CROs with invalid app name",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"test-app","commercialAppName":"test-app","providerSubaccountId":"` + providerSubaccountId + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: ResourceNotFound,
			},
		},
		{
			name:               "Provisioning Request valid",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","providerSubaccountId":"` + providerSubaccountId + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid with additional data and existing subscription",
			method:               http.MethodPut,
			body:                 `{"rootApplication":{"appName":"` + appName + `","providerSubaccountId":"` + providerSubaccountId + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:           true,
			withAdditionalData:   true,
			existingSubscription: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceUpdated,
			},
		},
		{
			name:                 "Provisioning Request with existing subscription but different subscriptionGUID",
			method:               http.MethodPut,
			body:                 `{"rootApplication":{"appName":"` + appName + `","providerSubaccountId":"` + providerSubaccountId + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + "update" + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:           true,
			existingSubscription: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceUpdated,
			},
		},
	}

	// Create and encode the client certificate once before all tests are executed
	certBytes, _ := os.ReadFile("testdata/rootCA.pem")
	certStr := strings.TrimSpace(string(certBytes))
	encodedCert := url.QueryEscape(certStr)

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				subPro := createSubscriptionProvider(SMS)
				if testData.withAdditionalData {
					if !testData.invalidAdditionalData {
						subPro.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{\"foo\":\"bar\"}"}
					} else {
						subPro.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{foo\":\"bar\"}"} //invalid json
					}
				}
				runtimeObjs = append(runtimeObjs, subPro)
			}
			if testData.existingSubscription {
				runtimeObjs = append(runtimeObjs, createSubscription("", subscriptionGUID))
			}
			if testData.existingTenantOutput {
				runtimeObjs = append(runtimeObjs, &v1alpha2.CAPTenantOutput{ObjectMeta: v1.ObjectMeta{Name: subName, Namespace: v1.NamespaceDefault, Labels: map[string]string{LabelTenantId: tenantId}}, Spec: v1alpha2.CAPTenantOutputSpec{SubscriptionCallbackData: "{\"foo3\":\"bar3\"}"}})
			}

			secrets := createSmsSecret()
			subHandler := setup(nil, secrets, runtimeObjs...)

			res := httptest.NewRecorder()
			req := httptest.NewRequest(testData.method, SmsRequestPath, strings.NewReader(testData.body))

			req.Header.Set("X-Forwarded-Client-Cert", encodedCert)

			subHandler.HandleSMSRequest(res, req)
			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			// Get the relevant response
			decoder := json.NewDecoder(res.Body)
			var resType Result
			err := decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.Subscription != testData.expectedResponse.Subscription && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func Test_deprovisioning(t *testing.T) {
	tests := []struct {
		name                 string
		method               string
		createCROs           bool
		existingSubscription bool
		body                 string
		expectedStatusCode   int
		expectedResponse     Result
	}{
		{
			name:               "Invalid Deprovisioning Request",
			method:             http.MethodDelete,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF",
			},
		},
		{
			name:               "Deprovisioning Request without SubscriptionProvider and Subscription",
			method:             http.MethodDelete,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: SubscriptionNotFound,
			},
		},
		{
			name:               "Deprovisioning Request valid without existing subscription",
			method:             http.MethodDelete,
			createCROs:         true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: SubscriptionNotFound,
			},
		},
		{
			name:                 "Deprovisioning Request valid existing subscription",
			method:               http.MethodDelete,
			createCROs:           true,
			existingSubscription: true,
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				runtimeObjs = append(runtimeObjs, createSubscriptionProvider(SaaS))
			}
			if testData.existingSubscription {
				runtimeObjs = append(runtimeObjs, createSubscription("", subscriptionGUID))
			}

			// set custom client for testing
			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			subHandler := setup(client, createSecrets(), runtimeObjs...)

			res := httptest.NewRecorder()
			req := httptest.NewRequest(testData.method, RequestPath, strings.NewReader(testData.body))
			req.Header.Set("Authorization", "Bearer "+tokenString)
			subHandler.HandleSaaSRequest(res, req)
			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			// Get the relevant response
			decoder := json.NewDecoder(res.Body)
			var resType Result
			err = decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.Subscription != testData.expectedResponse.Subscription && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func Test_sms_deprovisioning(t *testing.T) {
	tests := []struct {
		name                 string
		method               string
		invalidReqUrl        bool
		createCROs           bool
		existingSubscription bool
		expectedStatusCode   int
		expectedResponse     Result
	}{
		{
			name:               "Invalid Deprovisioning Request",
			method:             http.MethodDelete,
			invalidReqUrl:      true,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF",
			},
		},
		{
			name:               "Deprovisioning Request without SubscriptionProvider and Subscription",
			method:             http.MethodDelete,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: SubscriptionNotFound,
			},
		},
		{
			name:               "Deprovisioning Request valid without existing subscription",
			method:             http.MethodDelete,
			createCROs:         true,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: SubscriptionNotFound,
			},
		},
		{
			name:                 "Deprovisioning Request valid existing subscription",
			method:               http.MethodDelete,
			createCROs:           true,
			existingSubscription: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				runtimeObjs = append(runtimeObjs, createSubscriptionProvider(SMS))
			}
			if testData.existingSubscription {
				runtimeObjs = append(runtimeObjs, createSubscription("", subscriptionGUID))
			}

			subHandler := setup(nil, createSmsSecret(), runtimeObjs...)

			res := httptest.NewRecorder()

			requestTarget := SmsRequestPath + "/" + tenantId + "?ownServiceInstance=2123asda-abcd-49ee-be20-8a4dsadasd&planName&subscriptionGUID=" + subscriptionGUID
			if testData.invalidReqUrl {
				requestTarget = SmsRequestPath + "/" + tenantId + "?ownServiceInstance=2123asda-abcd-49ee-be20-8a4dsadasd&planName"
			}

			req := httptest.NewRequest(testData.method, requestTarget, nil)

			certBytes, _ := os.ReadFile("testdata/rootCA.pem")
			certStr := strings.TrimSpace(string(certBytes))
			encodedCert := url.QueryEscape(certStr)

			req.Header.Set("X-Forwarded-Client-Cert", encodedCert)
			subHandler.HandleSMSRequest(res, req)
			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			// Get the relevant response
			decoder := json.NewDecoder(res.Body)
			var resType Result
			err := decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.Subscription != testData.expectedResponse.Subscription && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func getX509KeyPair(t *testing.T) (string, string) {
	read := func(file string) string {
		value, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("error reading domain key pair: %s", err.Error())
		}
		return string(value)
	}
	return read("testdata/auth.service.local.crt"), read("testdata/auth.service.local.key")
}

func TestAsyncCallback(t *testing.T) {
	certValue, keyValue := getX509KeyPair(t)
	type testConfig struct {
		testName          string
		status            bool
		useCredentialType string
		additionalData    *map[string]any
		isProvisioning    bool
	}
	saasData := &util.SaasRegistryCredentials{
		SaasManagerUrl: "https://saas-manager.auth.service.local",
		CredentialData: util.CredentialData{
			CredentialType: "x509",
			ClientId:       "randomapp!b14",
			AuthUrl:        "https://secret.auth.service.local",
			UAADomain:      "auth.service.local",
			Certificate:    certValue,
			CertificateKey: keyValue,
			CertificateUrl: "https://cert.auth.service.local",
		},
	}
	smsData := &util.SmsCredentials{
		SubscriptionManagerUrl: "https://saas-manager.auth.service.local",
		CredentialData: util.CredentialData{
			CredentialType: "x509",
			ClientId:       "randomapp!b14",
			AuthUrl:        "https://secret.auth.service.local",
			UAADomain:      "auth.service.local",
			Certificate:    certValue,
			CertificateKey: keyValue,
			CertificateUrl: "https://cert.auth.service.local",
		},
	}

	type testContextKey string
	const cKey testContextKey = "async-callback-test"
	createCallbackTestServer := func(ctx context.Context, t *testing.T, params *testConfig, subscriptionType subscriptionType) *http.Client {
		// NOTE: reusing the wildcard domain and certificates for *.auth.service.local

		// Append CA cert to the system pool
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certs, err := os.ReadFile("testdata/rootCA.pem")
		if err != nil {
			t.Fatalf("error reading root CA certificate: %s", err.Error())
		}
		rootCAs.AppendCertsFromPEM(certs)

		var calledHost string
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/oauth/token":
				t.Log(calledHost)
				var expectedHostPattern string
				if params.useCredentialType == "x509" {
					expectedHostPattern = "cert.auth.service.local:"
				} else {
					expectedHostPattern = "secret.auth.service.local:"
				}
				if !strings.Contains(calledHost, expectedHostPattern) {
					t.Error("wrong host for token fetch")
				}
				w.Write([]byte("{\"access_token\": \"test-server-access-token\"}"))
			case "/async/callback":
				if !strings.Contains(calledHost, "saas-manager.auth.service.local:") {
					t.Error("wrong host for async callback")
				}
				if r.Header.Get("Authorization") != "Bearer test-server-access-token" {
					t.Error("expected authorization header with token in async callback")
				}

				var payload any
				switch subscriptionType {
				case SaaS:
					payload = &SaaSCallbackResponse{}
				case SMS:
					payload = &SmsCallbackResponse{}
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("could not read callback request body: %s", err.Error())
				}
				t.Logf("Async callback payload = %s", body)
				err = json.Unmarshal(body, payload)
				if err != nil {
					t.Fatalf("could not parse callback request body: %s", err.Error())
				}

				switch subscriptionType {
				case SaaS:
					payload := payload.(*SaaSCallbackResponse)
					if (params.status && payload.Status != CallbackSucceeded) || (!params.status && payload.Status != CallbackFailed) {
						t.Fatalf("status %s does not match status initiated from callback", payload.Status)
					}
					if params.isProvisioning {
						if strings.Index(payload.Message, "Provisioning ") != 0 {
							t.Fatal("incorrect message in payload")
						}
					} else {
						if strings.Index(payload.Message, "Deprovisioning ") != 0 {
							t.Fatal("incorrect message in payload")
						}
					}
					if params.additionalData != nil && payload.AdditionalOutput == nil {
						t.Fatal("expected additional output in payload")
					}
					if payload.SubscriptionUrl != "https://app.cluster.local" {
						t.Fatal("expected subscription URL to match the one provided in callback")
					}
				case SMS:
					payload := payload.(*SmsCallbackResponse)
					if (params.status && payload.Status != CallbackSucceeded) || (!params.status && payload.Status != CallbackFailed) {
						t.Fatalf("status %s does not match status initiated from callback", payload.Status)
					}
					if params.isProvisioning {
						if strings.Index(payload.Message, "Provisioning ") != 0 {
							t.Fatal("incorrect message in payload")
						}
					} else {
						if strings.Index(payload.Message, "Deprovisioning ") != 0 {
							t.Fatal("incorrect message in payload")
						}
					}
					if params.additionalData != nil && payload.AdditionalOutput == nil {
						t.Fatal("expected additional output in payload")
					}
					if payload.ApplicationUrl != "https://app.cluster.local" {
						t.Fatal("expected application URL to match the one provided in callback")
					}
				}

				w.WriteHeader(200)
			}
		}))
		cert, err := tls.X509KeyPair([]byte(certValue), []byte(keyValue))
		if err != nil {
			t.Fatalf("error reading domain key pair: %s", err.Error())
		}
		ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: rootCAs}
		ts.StartTLS()

		// adjust client to have custom domain resolution
		client := ts.Client()
		client.Transport = &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				if strings.Contains(addr, "auth.service.local:") {
					if c.Value(cKey) != nil {
						calledHost = addr
					} else {
						calledHost = ""
					}
					addr = ts.Listener.Addr().String()
				}
				return net.Dial(network, addr)
			},
			TLSClientConfig: ts.TLS,
		}

		go func() {
			<-ctx.Done()
			ts.Close()
		}()
		return client
	}

	tests := []testConfig{
		{testName: "saas_1", status: true, useCredentialType: "x509", isProvisioning: true},
		{testName: "sass_2", status: true, useCredentialType: "x509", isProvisioning: false},
		{testName: "sass_3", status: false, useCredentialType: "instance-secret", isProvisioning: true},
		{testName: "sass_4", status: false, useCredentialType: "instance-secret", additionalData: &map[string]any{"foo": "bar"}, isProvisioning: true},
		{testName: "saas_5", status: false, useCredentialType: "x509", additionalData: &map[string]any{"foo1": "bar2", "someKey": &map[string]string{"name": "key", "plan": "none"}}, isProvisioning: true},
	}

	ctx := context.WithValue(context.Background(), cKey, true)
	for _, p := range tests {
		saasData.CredentialType = p.useCredentialType
		t.Run(p.testName, func(t *testing.T) {
			client := createCallbackTestServer(context.TODO(), t, &p, SaaS)
			subHandler := setup(client, createSecrets())
			callbackReqInfo := subHandler.getCallbackReqInfo(SaaS, "/saas-manager/v1/subscription-callback/1234567/result", saasData, nil)
			subHandler.handleAsyncCallback(
				ctx,
				callbackReqInfo,
				p.status,
				"/async/callback",
				"https://app.cluster.local",
				p.additionalData,
				p.isProvisioning,
			)
		})
	}

	testsSms := []testConfig{
		{testName: "sms_1", status: true, useCredentialType: "x509", isProvisioning: true},
		{testName: "sms_2", status: true, useCredentialType: "x509", isProvisioning: false},
		{testName: "sms_3", status: false, useCredentialType: "instance-secret", isProvisioning: true},
		{testName: "sms_4", status: false, useCredentialType: "instance-secret", additionalData: &map[string]any{"foo": "bar"}, isProvisioning: true},
		{testName: "sms_5", status: false, useCredentialType: "x509", additionalData: &map[string]any{"foo1": "bar2", "someKey": &map[string]string{"name": "key", "plan": "none"}}, isProvisioning: true},
	}

	for _, p := range testsSms {
		smsData.CredentialType = p.useCredentialType
		t.Run(p.testName, func(t *testing.T) {
			client := createCallbackTestServer(context.TODO(), t, &p, SMS)
			subHandler := setup(client, createSmsSecret())
			callbackReqInfo := subHandler.getCallbackReqInfo(SMS, "/subscription-manager/v1/subscription-callback/12345678/result", nil, smsData)
			subHandler.handleAsyncCallback(
				ctx,
				callbackReqInfo,
				p.status,
				"/async/callback",
				"https://app.cluster.local",
				p.additionalData,
				p.isProvisioning,
			)
		})
	}
}

func TestCheckSubscriptionStatusContextCancellationAsyncTimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Subscription Status Context Cancellation AsyncTimeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// test context cancellation (like deadline)
		subHandler := setup(nil, createSecrets())
		type result struct {
			ready bool
			url   string
		}
		notify := make(chan result)
		go func() {
			ready, url := subHandler.checkSubscriptionStatus(context.Background(), "default", "test-sub", true, "4000")
			notify <- result{ready, url}
		}()

		timeout := time.After(8 * time.Second) // this is greater than the sleep duration of the subscription check routine

		select {
		case r := <-notify:
			if r.ready != false {
				t.Error("expected subscription check to return false")
			}
		case <-timeout:
			t.Fatal("failed to cancel subscription check routine")
		}
	})
}

func TestCheckSubscriptionStatusReady(t *testing.T) {
	sub := createSubscription(v1alpha2.SubscriptionStateReady, subscriptionGUID)
	sub.Status.Url = "https://" + subDomain + ".auth.service.local"
	subHandler := setup(nil, createSecrets(), sub)
	ready, u := subHandler.checkSubscriptionStatus(context.TODO(), sub.Namespace, sub.Name, true, "")

	if !ready {
		t.Error("expected subscription check to return true")
	}
	if u != sub.Status.Url {
		t.Errorf("expected subscription url %q, got %q", sub.Status.Url, u)
	}
}

func TestCheckSubscriptionStatusWithCallbacktimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Subscription Status With Callback timeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// subscription not ready --> should time out
		sub := createSubscription("", subscriptionGUID)
		subHandler := setup(nil, createSecrets(), sub)
		ready, _ := subHandler.checkSubscriptionStatus(context.TODO(), sub.Namespace, sub.Name, true, "4000")

		if ready != false {
			t.Error("expected subscription check to return false, due to timeout (async callback timeout exceeded)")
		}
	})
}

func execTestsWithBLI(t *testing.T, name string, backlogItems []string, test func(t *testing.T)) {
	t.Run(name+", BLIs: "+strings.Join(backlogItems, ", "), test)
}

func TestGetDependencies(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		invalidToken       bool
		invalidURI         bool
		noDependencies     bool
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:               "Invalid get dependency request - wrong method",
			method:             http.MethodPut,
			expectedStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name:               "Not authorized request",
			method:             http.MethodGet,
			invalidToken:       true,
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "Invalid URI",
			method:             http.MethodGet,
			invalidURI:         true,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "Valid get dependency request",
			method:             http.MethodGet,
			expectedStatusCode: http.StatusOK,
			expectedResponse:   dependenciesJSON,
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			subPro := createSubscriptionProvider(SaaS)
			if testData.noDependencies {
				subPro.Spec.Dependencies = ""
			}

			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}
			subHandler := setup(client, createSecrets(), subPro)

			res := httptest.NewRecorder()
			var req *http.Request
			if testData.invalidURI {
				req = httptest.NewRequest(testData.method, "/callback/dependencies/providerSubaccountId/{appName}", nil)
				req.SetPathValue("appName", appName)
			} else {
				req = httptest.NewRequest(testData.method, "/dependencies/{providerSubaccountId}/{appName}", nil)
				req.SetPathValue("providerSubaccountId", providerSubaccountId)
				req.SetPathValue("appName", appName)
			}

			if testData.invalidToken {
				tokenString = "abc" //invalid token
			}

			req.Header.Set("Authorization", "Bearer "+tokenString)
			subHandler.HandleSaaSGetDependenciesRequest(res, req)

			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			// Get the relevant response
			if res.Code == http.StatusOK {
				resBodyStr := res.Body.String()
				if resBodyStr != testData.expectedResponse {
					t.Error("Unexpected response: ", res.Body, " expected: ", testData.expectedResponse)
				}
			}
		})
	}
}

func TestGetSMSDependencies(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		invalidCert        bool
		invalidURI         bool
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:               "Invalid get SMS dependency request - wrong method",
			method:             http.MethodPut,
			expectedStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name:               "Not authorized SMS request - invalid certificate",
			method:             http.MethodGet,
			invalidCert:        true,
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "Invalid URI",
			method:             http.MethodGet,
			invalidURI:         true,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "Valid get SMS dependency request",
			method:             http.MethodGet,
			expectedStatusCode: http.StatusOK,
			expectedResponse:   dependenciesJSON,
		},
	}

	certBytes, _ := os.ReadFile("testdata/rootCA.pem")
	certStr := strings.TrimSpace(string(certBytes))
	encodedCert := url.QueryEscape(certStr)

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			subPro := createSubscriptionProvider(SMS)
			subHandler := setup(nil, createSmsSecret(), subPro)

			res := httptest.NewRecorder()
			var req *http.Request
			if testData.invalidURI {
				req = httptest.NewRequest(testData.method, "/sms/dependencies/providerSubaccountId/{appName}", nil)
				req.SetPathValue("appName", appName)
			} else {
				req = httptest.NewRequest(testData.method, "/sms/dependencies/{providerSubaccountId}/{appName}", nil)
				req.SetPathValue("providerSubaccountId", providerSubaccountId)
				req.SetPathValue("appName", appName)
			}

			if testData.invalidCert {
				req.Header.Set("X-Forwarded-Client-Cert", "invalid-cert")
			} else {
				req.Header.Set("X-Forwarded-Client-Cert", encodedCert)
			}

			subHandler.HandleSMSGetDependenciesRequest(res, req)

			if res.Code != testData.expectedStatusCode {
				t.Errorf("Expected status '%d', received '%d'", testData.expectedStatusCode, res.Code)
			}

			if res.Code == http.StatusOK {
				resBodyStr := res.Body.String()
				if resBodyStr != testData.expectedResponse {
					t.Error("Unexpected response: ", res.Body, " expected: ", testData.expectedResponse)
				}
			}
		})
	}
}

func TestGetDependenciesAuthError_Error(t *testing.T) {
	err := &GetDependenciesAuthError{}
	if err.Error() != "Not authorized" {
		t.Errorf("expected 'Not authorized', got: %s", err.Error())
	}
}

func TestGetSubscriptionDomain(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected string
	}{
		{
			name: "subscriptionDomain present",
			payload: map[string]any{
				"subscriptionParams": map[string]any{
					"subscriptionDomain": "my-domain.test.local",
				},
			},
			expected: "my-domain.test.local",
		},
		{
			name:     "no subscriptionParams",
			payload:  map[string]any{"foo": "bar"},
			expected: "",
		},
		{
			name: "subscriptionParams is not a map",
			payload: map[string]any{
				"subscriptionParams": "not-a-map",
			},
			expected: "",
		},
		{
			name: "subscriptionParams without subscriptionDomain",
			payload: map[string]any{
				"subscriptionParams": map[string]any{
					"someOtherParam": "value",
				},
			},
			expected: "",
		},
		{
			name:     "empty payload",
			payload:  map[string]any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSubscriptionDomain(tt.payload); got != tt.expected {
				t.Errorf("getSubscriptionDomain() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetXSUAADetails_MissingAuthSecret(t *testing.T) {
	s := setup(nil, nil)
	subPro := &v1alpha2.SubscriptionProvider{
		ObjectMeta: v1.ObjectMeta{Name: providerName, Namespace: v1.NamespaceDefault},
		Spec: v1alpha2.SubscriptionProviderSpec{
			SubscriptionInfo: v1alpha2.SubscriptionInfo{AuthSecret: ""},
		},
	}
	if result := s.getXSUAADetails(subPro, TenantProvisioning); result != nil {
		t.Errorf("expected nil XSUAA credentials when auth secret is missing, got: %+v", result)
	}
}

func TestEnrichAdditionalOutput(t *testing.T) {
	tenantOutput := &v1alpha2.CAPTenantOutput{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-output",
			Namespace: v1.NamespaceDefault,
			Labels:    map[string]string{LabelTenantId: tenantId},
		},
		Spec: v1alpha2.CAPTenantOutputSpec{
			SubscriptionCallbackData: `{"key1":"value1","key2":"value2"}`,
		},
	}
	s := setup(nil, nil, tenantOutput)

	additionalOutput := map[string]any{"existing": "data"}
	if err := s.enrichAdditionalOutput(v1.NamespaceDefault, tenantId, &additionalOutput); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// the existing data should be retained and the tenant output merged in
	if additionalOutput["existing"] != "data" {
		t.Errorf("expected existing data to be retained, got: %+v", additionalOutput)
	}
	if additionalOutput["key1"] != "value1" || additionalOutput["key2"] != "value2" {
		t.Errorf("expected tenant output to be merged, got: %+v", additionalOutput)
	}
}

func TestEnrichAdditionalOutput_InvalidCallbackData(t *testing.T) {
	tenantOutput := &v1alpha2.CAPTenantOutput{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-output-invalid",
			Namespace: v1.NamespaceDefault,
			Labels:    map[string]string{LabelTenantId: tenantId},
		},
		Spec: v1alpha2.CAPTenantOutputSpec{
			SubscriptionCallbackData: `{invalid-json`,
		},
	}
	s := setup(nil, nil, tenantOutput)

	additionalOutput := map[string]any{}
	if err := s.enrichAdditionalOutput(v1.NamespaceDefault, tenantId, &additionalOutput); err == nil {
		t.Error("expected an error when the callback data is invalid JSON")
	}
}

func TestEnrichAdditionalOutput_NoMatchingTenantOutputs(t *testing.T) {
	s := setup(nil, nil)
	additionalOutput := map[string]any{"existing": "data"}
	if err := s.enrichAdditionalOutput(v1.NamespaceDefault, tenantId, &additionalOutput); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(additionalOutput) != 1 || additionalOutput["existing"] != "data" {
		t.Errorf("expected additional output to be unchanged, got: %+v", additionalOutput)
	}
}

// TestCheckSubscriptionLimit_LimitReached verifies that a provisioning request returns HTTP 422
// when the MaxSubscriptions limit is already reached.
func TestCheckSubscriptionLimit_LimitReached(t *testing.T) {
	maxSubs := int32(1)
	subPro := createSubscriptionProvider(SaaS)
	subPro.Spec.MaxSubscriptions = &maxSubs
	appIdHash := sha1Sum(providerSubaccountId, appName)
	// Existing subscription for a different tenant – counts towards the MaxSubscriptions limit.
	existingSub := &v1alpha2.Subscription{
		ObjectMeta: v1.ObjectMeta{
			Name:      "other-tenant-sub",
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelAppIdHash: appIdHash,
				LabelTenantId:  tenantId + "-other",
			},
		},
		Spec: v1alpha2.SubscriptionSpec{
			AppName:              appName,
			ProviderSubaccountId: providerSubaccountId,
			TenantId:             tenantId + "-other",
		},
	}

	client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
	if err != nil {
		t.Fatal(err.Error())
	}

	subHandler := setup(client, createSecrets(), subPro, existingSub)

	body := `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, RequestPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenString)
	subHandler.HandleSaaSRequest(res, req)

	if res.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected HTTP %d, got %d", http.StatusUnprocessableEntity, res.Code)
	}
	var result Result
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal("unexpected error decoding response:", err)
	}
	if result.Message != SubscriptionLimitReached {
		t.Errorf("expected message %q, got %q", SubscriptionLimitReached, result.Message)
	}
}

// TestCheckSubscriptionLimit_APIError verifies that a k8s API failure during the limit check
// causes the provisioning request to return HTTP 500 (reject, do not fail open).
func TestCheckSubscriptionLimit_APIError(t *testing.T) {
	maxSubs := int32(10)
	subPro := createSubscriptionProvider(SaaS)
	subPro.Spec.MaxSubscriptions = &maxSubs
	fakeClient := fake.NewSimpleClientset(subPro)
	fakeClient.PrependReactor("list", "subscriptions", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("simulated k8s api error")
	})

	client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
	if err != nil {
		t.Fatal(err.Error())
	}

	subHandler := NewSubscriptionHandler(fakeClient, k8sfake.NewSimpleClientset(createSecrets()...))
	subHandler.httpClientGenerator = &httpTestClientGenerator{client: client}

	body := `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","providerSubaccountId":"` + providerSubaccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, RequestPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenString)
	subHandler.HandleSaaSRequest(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Errorf("expected HTTP %d, got %d", http.StatusInternalServerError, res.Code)
	}
}
