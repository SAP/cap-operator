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

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
)

const RequestPath = "/provision"
const SmsRequestPath = "/sms/provision/tenants"

type httpTestClientGenerator struct {
	client *http.Client
}

func (facade *httpTestClientGenerator) NewHTTPClient() *http.Client { return facade.client }

const (
	caName                        = "ca-test-controller"
	catName                       = caName + "-provider"
	appName                       = "some-app-name"
	globalAccountId               = "cap-app-global"
	subDomain                     = "foo"
	tenantId                      = "012012012-1234-1234-123456"
	subscriptionGUID              = "012301234-2345-6789-ABCDEF"
	subscriptionContextSecretName = catName + "-context"
)

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
			Name:      "test-xsuaa-sec2",
			Namespace: v1.NamespaceDefault,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"credentials": []byte(`{
				"uaadomain": "auth2.service.local",
				"xsappname": "appname!b21",
				"trustedclientidsuffix": "|appname!b21",
				"verificationkey": "",
				"sburl": "internal.auth2.service.local",
				"url": "https://app2-domain.auth2.service.local",
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

func createTenantSubscriptionContextSecret(subscriptionContext string) runtime.Object {
	return &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      subscriptionContextSecretName,
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, appName),
				LabelTenantId:                     tenantId,
				LabelSubscriptionGUID:             subscriptionGUID,
			},
		},
		StringData: map[string]string{
			"subscriptionContext": subscriptionContext,
		},
	}
}

func createCA() *v1alpha1.CAPApplication {
	return &v1alpha1.CAPApplication{
		ObjectMeta: v1.ObjectMeta{
			Name:      caName,
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, appName),
			},
		},
		Spec: v1alpha1.CAPApplicationSpec{
			GlobalAccountId: globalAccountId,
			BTPAppName:      appName,
			Provider: &v1alpha1.BTPTenantIdentification{
				SubDomain: subDomain,
				TenantId:  tenantId,
			},
			BTP: v1alpha1.BTP{
				Services: []v1alpha1.ServiceInfo{
					{
						Class:  "xsuaa",
						Name:   "test-xsuaa",
						Secret: "test-xsuaa-sec",
					},
					{
						Class:  "xsuaa",
						Name:   "test-xsuaa2",
						Secret: "test-xsuaa-sec2",
					},
					{
						Class:  "saas-registry",
						Name:   "test-saas",
						Secret: "test-saas-sec",
					},
					{
						Class:  "service-manager",
						Name:   "test-sm",
						Secret: "test-sm-sec",
					},
					{
						Class:  "destination",
						Name:   "test-dest",
						Secret: "test-dest-sec",
					},
					{
						Class:  "html5-apps-repo",
						Name:   "test-html-host",
						Secret: "test-html-host-sec",
					},
					{
						Class:  "html5-apps-repo",
						Name:   "test-html-rt",
						Secret: "test-html-rt-sec",
					},
					{
						Class:  "subscription-manager",
						Name:   "test-sms",
						Secret: "test-sms-sec",
					},
				},
			},
		},
	}
}

func createCAT(ready bool, withGlobalTenantId ...bool) *v1alpha1.CAPTenant {
	cat := &v1alpha1.CAPTenant{
		ObjectMeta: v1.ObjectMeta{
			Name:      catName,
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, appName),
				LabelTenantId:                     tenantId,
			},
			Annotations: map[string]string{
				AnnotationSubscriptionContextSecret: subscriptionContextSecretName,
			},
		},
		Spec: v1alpha1.CAPTenantSpec{
			CAPApplicationInstance: caName,
			BTPTenantIdentification: v1alpha1.BTPTenantIdentification{
				SubDomain: subDomain,
				TenantId:  tenantId,
			},
		},
	}
	if withGlobalTenantId != nil && withGlobalTenantId[0] {
		cat.ObjectMeta.Labels[LabelSubscriptionGUID] = subscriptionGUID
	}
	if ready {
		cat.Status = v1alpha1.CAPTenantStatus{
			State:                                v1alpha1.CAPTenantStateReady,
			CurrentCAPApplicationVersionInstance: "cap-version",
			GenericStatus: v1alpha1.GenericStatus{
				Conditions: []v1.Condition{{
					Type:   string(v1alpha1.ConditionTypeReady),
					Status: "True",
					Reason: "TenantReady",
				}},
			},
		}
	}
	return cat
}

func createDomain() *v1alpha1.Domain {
	return &v1alpha1.Domain{
		ObjectMeta: v1.ObjectMeta{
			Name:      "primary-domain",
			Namespace: v1.NamespaceDefault,
		},
		Spec: v1alpha1.DomainSpec{
			Domain: "auth.service.local",
			IngressSelector: map[string]string{
				"istio": "ingressgateway",
				"app":   "istio-ingressgateway",
			},
			TLSMode:   v1alpha1.TlsModeSimple,
			DNSTarget: "in.service.local",
		},
	}
}

func createClusterDomain() *v1alpha1.ClusterDomain {
	return &v1alpha1.ClusterDomain{
		ObjectMeta: v1.ObjectMeta{
			Name: "external-domain",
		},
		Spec: v1alpha1.DomainSpec{
			Domain: "external.service.sap",
			IngressSelector: map[string]string{
				"istio": "ingressgateway",
				"app":   "istio-ingressgateway",
			},
			TLSMode:   v1alpha1.TlsModeSimple,
			DNSTarget: "in.service.sap",
		},
	}
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

	if resType.tenant != nil && resType.Message != InvalidRequestMethod {
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
		withSecretKey         bool
		existingTenant        bool
		existingTenantOutput  bool
		expectedStatusCode    int
		expectedResponse      Result
		existingDomain        bool
		existingClusterDomain bool
		invalidDomain         bool
		invalidClusterDomain  bool
	}{
		{
			name:               "Invalid Provisioning Request",
			method:             http.MethodPut,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF", //TODO
			},
		},
		{
			name:               "Provisioning Request without CROs",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Provisioning Request with CROs with invalid app name",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"test-app","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "", //TODO
			},
		},
		{
			name:               "Provisioning Request valid (without domains)",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid (invalid domain)",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			invalidDomain:      true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid (invalid clusterdomains)",
			method:               http.MethodPut,
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:           true,
			invalidClusterDomain: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid (with domain)",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			existingDomain:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                  "Provisioning Request valid (with Cluster domain)",
			method:                http.MethodPut,
			body:                  `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:            true,
			existingClusterDomain: true,
			expectedStatusCode:    http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid with additional data and existing tenant",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			withAdditionalData: true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid with additional data and existing tenant and existing tenant output",
			method:               http.MethodPut,
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:           true,
			withAdditionalData:   true,
			existingTenant:       true,
			existingTenantOutput: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                  "Provisioning Request valid with invalid additional data and existing tenant",
			method:                http.MethodPut,
			body:                  `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:            true,
			withAdditionalData:    true,
			invalidAdditionalData: true,
			existingTenant:        true,
			expectedStatusCode:    http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request with existing tenant",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceFound,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			var ca *v1alpha1.CAPApplication
			var cat *v1alpha1.CAPTenant
			var ctout *v1alpha1.CAPTenantOutput
			runtimeObjs := []runtime.Object{}
			if testData.existingDomain {
				runtimeObjs = append(runtimeObjs, createDomain())
			} else if testData.existingClusterDomain {
				runtimeObjs = append(runtimeObjs, createClusterDomain())
			}
			if testData.createCROs {
				ca = createCA()
				if testData.withAdditionalData {
					if !testData.invalidAdditionalData {
						ca.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{\"foo\":\"bar\"}"}
					} else {
						ca.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{foo\":\"bar\"}"} //invalid json
					}
				}
				// Update the CA with the correct domainRefs if needed
				if testData.existingDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "Domain", Name: "primary-domain"}}
				} else if testData.existingClusterDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "ClusterDomain", Name: "external-domain"}}
				} else if testData.invalidDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "Domain", Name: "foo"}}
				} else if testData.invalidClusterDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "ClusterDomain", Name: "foo"}}
				}
				runtimeObjs = append(runtimeObjs, ca)
			}
			if testData.existingTenant {
				cat = createCAT(testData.withAdditionalData, true)
				runtimeObjs = append(runtimeObjs, cat)
			}
			if testData.existingTenantOutput {
				ctout = &v1alpha1.CAPTenantOutput{ObjectMeta: v1.ObjectMeta{Name: catName, Namespace: v1.NamespaceDefault, Labels: map[string]string{LabelTenantId: tenantId}}, Spec: v1alpha1.CAPTenantOutputSpec{SubscriptionCallbackData: "{\"foo3\":\"bar3\"}"}}
				runtimeObjs = append(runtimeObjs, ctout)
			}

			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			secrets := createSecrets()
			if testData.existingTenant {
				secrets = append(secrets, createTenantSubscriptionContextSecret(testData.body))
			}
			subHandler := setup(client, secrets, runtimeObjs...)

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

			if resType.tenant != testData.expectedResponse.tenant && resType.Message != testData.expectedResponse.Message {
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
		withSecretKey         bool
		existingTenant        bool
		existingTenantOutput  bool
		expectedStatusCode    int
		expectedResponse      Result
		existingDomain        bool
		existingClusterDomain bool
		invalidDomain         bool
		invalidClusterDomain  bool
	}{
		{
			name:               "Invalid Provisioning Request",
			method:             http.MethodPut,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF", //TODO
			},
		},
		{
			name:               "Provisioning Request without CROs",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Provisioning Request with CROs with invalid app name",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"test-app","commercialAppName":"test-app"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "", //TODO
			},
		},
		{
			name:               "Provisioning Request valid (without domains)",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid (invalid domain)",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			invalidDomain:      true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid (invalid clusterdomains)",
			method:               http.MethodPut,
			body:                 `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:           true,
			invalidClusterDomain: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid (with domain)",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			existingDomain:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                  "Provisioning Request valid (with Cluster domain)",
			method:                http.MethodPut,
			body:                  `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:            true,
			existingClusterDomain: true,
			expectedStatusCode:    http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid with additional data and existing tenant",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			withAdditionalData: true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                 "Provisioning Request valid with additional data and existing tenant and existing tenant output",
			method:               http.MethodPut,
			body:                 `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:           true,
			withAdditionalData:   true,
			existingTenant:       true,
			existingTenantOutput: true,
			expectedStatusCode:   http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:                  "Provisioning Request valid with invalid additional data and existing tenant",
			method:                http.MethodPut,
			body:                  `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:            true,
			withAdditionalData:    true,
			invalidAdditionalData: true,
			existingTenant:        true,
			expectedStatusCode:    http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request with existing tenant",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceFound,
			},
		},
		{
			name:               "Provisioning Request with existing tenant but different subscriptionGUID (If provisioning fails due to callback issue, the tenant exists and in BTP provisioned failed; retriggering sends a new subscriptionGUID in the payload)",
			method:             http.MethodPut,
			body:               `{"rootApplication":{"appName":"` + appName + `","commercialAppName":"` + appName + `"},"subscriber":{"subscriptionGUID":"` + subscriptionGUID + "update" + `","app_tid":"` + tenantId + `","globalAccountId":"` + globalAccountId + `","subaccountSubdomain":"` + subDomain + `"}}`,
			createCROs:         true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
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
			var ca *v1alpha1.CAPApplication
			var cat *v1alpha1.CAPTenant
			var ctout *v1alpha1.CAPTenantOutput
			runtimeObjs := []runtime.Object{}
			if testData.existingDomain {
				runtimeObjs = append(runtimeObjs, createDomain())
			} else if testData.existingClusterDomain {
				runtimeObjs = append(runtimeObjs, createClusterDomain())
			}
			if testData.createCROs {
				ca = createCA()
				if testData.withAdditionalData {
					if !testData.invalidAdditionalData {
						ca.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{\"foo\":\"bar\"}"}
					} else {
						ca.Annotations = map[string]string{AnnotationSaaSAdditionalOutput: "{foo\":\"bar\"}"} //invalid json
					}
				}
				// Update the CA with the correct domainRefs if needed
				if testData.existingDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "Domain", Name: "primary-domain"}}
				} else if testData.existingClusterDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "ClusterDomain", Name: "external-domain"}}
				} else if testData.invalidDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "Domain", Name: "foo"}}
				} else if testData.invalidClusterDomain {
					ca.Spec.DomainRefs = []v1alpha1.DomainRef{{Kind: "ClusterDomain", Name: "foo"}}
				}
				runtimeObjs = append(runtimeObjs, ca)
			}
			if testData.existingTenant {
				cat = createCAT(testData.withAdditionalData, true)
				runtimeObjs = append(runtimeObjs, cat)
			}
			if testData.existingTenantOutput {
				ctout = &v1alpha1.CAPTenantOutput{ObjectMeta: v1.ObjectMeta{Name: catName, Namespace: v1.NamespaceDefault, Labels: map[string]string{LabelTenantId: tenantId}}, Spec: v1alpha1.CAPTenantOutputSpec{SubscriptionCallbackData: "{\"foo3\":\"bar3\"}"}}
				runtimeObjs = append(runtimeObjs, ctout)
			}

			client, _, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			secrets := createSmsSecret()
			if testData.existingTenant {
				secrets = append(secrets, createTenantSubscriptionContextSecret(testData.body))
			}
			subHandler := setup(client, secrets, runtimeObjs...)

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
			err = decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.tenant != testData.expectedResponse.tenant && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func Test_deprovisioning(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		createCROs         bool
		existingTenant     bool
		body               string
		expectedStatusCode int
		expectedResponse   Result
		withSecretKey      bool
		withGlobalTenantId bool
	}{
		{
			name:               "Invalid Deprovisioning Request",
			method:             http.MethodDelete,
			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF", //TODO
			},
		},
		{
			name:               "Deprovisioning Request without CAPApplication and CAPTenant",
			method:             http.MethodDelete,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Deprovisioning Request valid without existing tenant)",
			method:             http.MethodDelete,
			createCROs:         true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
		{
			name:               "Deprovisioning Request valid existing tenant",
			method:             http.MethodDelete,
			createCROs:         true,
			existingTenant:     true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
		{
			name:               "Deprovisioning Request valid existing tenant having global tenant id",
			method:             http.MethodDelete,
			createCROs:         true,
			existingTenant:     true,
			withGlobalTenantId: true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscriptionGUID":"` + subscriptionGUID + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			var ca *v1alpha1.CAPApplication
			var cat *v1alpha1.CAPTenant
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				ca = createCA()
				runtimeObjs = append(runtimeObjs, ca)
			}
			if testData.existingTenant {
				cat = createCAT(false, testData.withGlobalTenantId)
				runtimeObjs = append(runtimeObjs, cat)
			}

			// set custom client for testing
			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			secrets := createSecrets()
			if testData.existingTenant {
				secrets = append(secrets, createTenantSubscriptionContextSecret(testData.body))
			}
			subHandler := setup(client, secrets, runtimeObjs...)

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

			if resType.tenant != testData.expectedResponse.tenant && resType.Message != testData.expectedResponse.Message {
				t.Error("Response: ", res.Body, " does not match expected result: ", testData.expectedResponse)
			}
		})
	}
}

func Test_sms_deprovisioning(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		invalidReqUrl      bool
		createCROs         bool
		existingTenant     bool
		expectedStatusCode int
		expectedResponse   Result
		withSecretKey      bool
	}{
		{
			name:               "Invalid Deprovisioning Request",
			method:             http.MethodDelete,
			invalidReqUrl:      true,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF", //TODO
			},
		},
		{
			name:               "Deprovisioning Request without CAPApplication and CAPTenant",
			method:             http.MethodDelete,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Deprovisioning Request valid without existing tenant",
			method:             http.MethodDelete,
			createCROs:         true,
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
		{
			name:               "Deprovisioning Request valid existing tenant",
			method:             http.MethodDelete,
			createCROs:         true,
			existingTenant:     true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			var ca *v1alpha1.CAPApplication
			var cat *v1alpha1.CAPTenant
			runtimeObjs := []runtime.Object{}
			if testData.createCROs {
				ca = createCA()
				runtimeObjs = append(runtimeObjs, ca)
			}
			if testData.existingTenant {
				cat = createCAT(false, true)
				runtimeObjs = append(runtimeObjs, cat)
			}

			// set custom client for testing
			client, _, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			secrets := createSmsSecret()
			if testData.existingTenant {
				secrets = append(secrets, createTenantSubscriptionContextSecret(`{"rootApplication":{"appName":"`+appName+`","commercialAppName":"`+appName+`"},"subscriber":{"subscriptionGUID":"`+subscriptionGUID+"update"+`","app_tid":"`+tenantId+`","globalAccountId":"`+globalAccountId+`","subaccountSubdomain":"`+subDomain+`"}}`))
			}

			subHandler := setup(client, secrets, runtimeObjs...)

			res := httptest.NewRecorder()

			requestTarget := SmsRequestPath + "/" + tenantId + "?ownServiceInstance=2123asda-abcd-49ee-be20-8a4dsadasd&planName&subscriptionGUID=" + subscriptionGUID
			if testData.invalidReqUrl {
				requestTarget = SmsRequestPath + "/" + tenantId + "?ownServiceInstance=2123asda-abcd-49ee-be20-8a4dsadasd&planName"
			}

			req := httptest.NewRequest(testData.method, requestTarget, nil)

			certBytes, err := os.ReadFile("testdata/rootCA.pem")
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
			err = decoder.Decode(&resType)
			if err != nil {
				t.Error("Unexpected error in expected response: ", res.Body)
			}

			if resType.tenant != testData.expectedResponse.tenant && resType.Message != testData.expectedResponse.Message {
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

		data, _ := json.Marshal(p.additionalData)
		ca := &v1alpha1.CAPApplication{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test-app",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationSubscriptionDomain:   "cluster.local",
					AnnotationSaaSAdditionalOutput: string(data),
				},
			},
		}
		t.Run(p.testName, func(t *testing.T) {
			client := createCallbackTestServer(context.TODO(), t, &p, SaaS)
			subHandler := setup(client, createSecrets())
			callbackReqInfo := subHandler.getCallbackReqInfo(SaaS, "/saas-manager/v1/subscription-callback/1234567/result", saasData, nil)
			step := TenantDeprovisioning
			if p.isProvisioning {
				step = TenantProvisioning
			}

			payload := subHandler.constructPayload(p.isProvisioning, p.status, callbackReqInfo.SubscriptionType, step, ca, tenantInfo{tenantSubDomain: "app", tenantId: "1234567890"})
			subHandler.handleAsyncCallback(
				ctx,
				callbackReqInfo,
				p.status,
				payload,
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

		data, _ := json.Marshal(p.additionalData)
		ca := &v1alpha1.CAPApplication{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test-app",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationSubscriptionDomain:   "cluster.local",
					AnnotationSaaSAdditionalOutput: string(data),
				},
			},
		}
		step := TenantDeprovisioning
		if p.isProvisioning {
			step = TenantProvisioning
		}
		t.Run(p.testName, func(t *testing.T) {
			client := createCallbackTestServer(context.TODO(), t, &p, SMS)
			subHandler := setup(client, createSmsSecret())
			callbackReqInfo := subHandler.getCallbackReqInfo(SMS, "/subscription-manager/v1/subscription-callback/12345678/result", nil, smsData)

			payload := subHandler.constructPayload(p.isProvisioning, p.status, callbackReqInfo.SubscriptionType, step, ca, tenantInfo{tenantSubDomain: "app", tenantId: "1234567890"})
			subHandler.handleAsyncCallback(
				ctx,
				callbackReqInfo,
				p.status,
				payload,
				p.isProvisioning,
			)
		})
	}
}

func TestCheckTenantStatusContextCancellationAsyncTimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Tenant Status Context Cancellation AsyncTimeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// test context cancellation (like deadline)
		subHandler := setup(nil, createSecrets())
		notify := make(chan bool)
		go func() {
			r := subHandler.checkCAPTenantStatus(context.Background(), "default", "test-cat", true, "4000")
			notify <- r
		}()

		timeout := time.After(6 * time.Second) // this is greater than the sleep duration of the tenant check routine

		select {
		case r := <-notify:
			if r != false {
				t.Error("expected tenant check to return false")
			}
		case <-timeout:
			t.Fatal("failed to cancel tenant check routine")
		}
	})
}

func TestCheckTenantStatusTenantReady(t *testing.T) {
	// test context cancellation (like deadline)
	cat := createCAT(true)
	subHandler := setup(nil, createSecrets(), cat)
	r := subHandler.checkCAPTenantStatus(context.TODO(), cat.Namespace, cat.Name, true, "")

	if r != true {
		t.Error("expected tenant check to return false")
	}
}

func TestCheckTenantStatusWithCallbacktimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Tenant Status With Callback timeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// test context cancellation (like deadline)
		cat := createCAT(false)
		subHandler := setup(nil, createSecrets(), cat)
		r := subHandler.checkCAPTenantStatus(context.TODO(), cat.Namespace, cat.Name, true, "4000")

		if r != false {
			t.Error("expected tenant check to return false, due to timeout (async callback timeout exceeded)")
		}
	})
}

func TestMultiXSUAA(t *testing.T) {
	execTestsWithBLI(t, "Check Multiple xsuaa services used in a CA", []string{"ERP4SMEPREPWORKAPPPLAT-3773"}, func(t *testing.T) {
		// CA without "sme.sap.com/primary-xsuaa" annotation
		ca := createCA()

		subHandler := setup(nil, createSecrets(), ca)
		uaaCreds := subHandler.getXSUAADetails(ca, "Test")

		if uaaCreds.AuthUrl != "https://app-domain.auth.service.local" {
			t.Error("incorrect uaa returned")
		}

		// CA with "sme.sap.com/primary-xsuaa" annotation
		ca2 := createCA()
		ca2.Annotations = map[string]string{
			util.AnnotationPrimaryXSUAA: "test-xsuaa2",
		}

		uaaCreds = subHandler.getXSUAADetails(ca2, "Test")

		if uaaCreds.AuthUrl != "https://app2-domain.auth2.service.local" {
			t.Error("incorrect uaa via annotations returned")
		}
	})
}

func execTestsWithBLI(t *testing.T, name string, backlogItems []string, test func(t *testing.T)) {
	t.Run(name+", BLIs: "+strings.Join(backlogItems, ", "), test)
}
