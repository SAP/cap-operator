/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
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

type httpTestClientGenerator struct {
	client *http.Client
}

func (facade *httpTestClientGenerator) NewHTTPClient() *http.Client { return facade.client }

const (
	cavName         = "cav-test-controller"
	caName          = "ca-test-controller"
	appName         = "some-app-name"
	globalAccountId = "cap-app-global"
	subDomain       = "foo"
	tenantId        = "012012012-1234-1234-123456"
)

func setup(client *http.Client, objects ...runtime.Object) *SubscriptionHandler {
	subHandler := NewSubscriptionHandler(fake.NewSimpleClientset(objects...), k8sfake.NewSimpleClientset(createSecrets()...))
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
			Provider: v1alpha1.BTPTenantIdentification{
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
				},
			},
		},
	}
}

func createCAT(ready bool) *v1alpha1.CAPTenant {
	cat := &v1alpha1.CAPTenant{
		ObjectMeta: v1.ObjectMeta{
			Name:      caName + "-provider",
			Namespace: v1.NamespaceDefault,
			Labels: map[string]string{
				LabelBTPApplicationIdentifierHash: sha1Sum(globalAccountId, appName),
				LabelTenantId:                     tenantId,
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
	req := httptest.NewRequest(http.MethodPatch, RequestPath, strings.NewReader(`{"subscriptionAppName":"`+appName+`","globalAccountGUID":"`+globalAccountId+`","subscribedTenantId":"`+tenantId+`","subscribedSubdomain":"`+subDomain+`"}`))
	subHandler := setup(nil)
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

	if resType.Tenant != nil && resType.Message != InvalidRequestMethod {
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
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Provisioning Request with CROs with invalid app name",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"test-app","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "", //TODO
			},
		},
		{
			name:               "Provisioning Request valid (without domains)",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			createCROs:         true,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceCreated,
			},
		},
		{
			name:               "Provisioning Request valid (invalid domain)",
			method:             http.MethodPut,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:                  `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:                 `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:                  `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
				cat = createCAT(testData.withAdditionalData)
				runtimeObjs = append(runtimeObjs, cat)
			}
			if testData.existingTenantOutput {
				ctout = &v1alpha1.CAPTenantOutput{ObjectMeta: v1.ObjectMeta{Name: caName + "-provider", Namespace: v1.NamespaceDefault, Labels: map[string]string{LabelTenantId: tenantId}}, Spec: v1alpha1.CAPTenantOutputSpec{SubscriptionCallbackData: "{\"foo3\":\"bar3\"}"}}
				runtimeObjs = append(runtimeObjs, ctout)
			}

			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}

			subHandler := setup(client, runtimeObjs...)

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

			if resType.Tenant != testData.expectedResponse.Tenant && resType.Message != testData.expectedResponse.Message {
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
	}{
		{
			name:   "Invalid Deprovisioning Request",
			method: http.MethodDelete,

			body:               "",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: Result{
				Message: "EOF", //TODO
			},
		},
		{
			name:   "Deprovisioning Request w/o CROs",
			method: http.MethodDelete,

			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusNotAcceptable,
			expectedResponse: Result{
				Message: "the server could not find the requested resource (get capapplications.sme.sap.com)", //TODO
			},
		},
		{
			name:               "Deprovisioning Request valid",
			method:             http.MethodDelete,
			createCROs:         true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
			expectedStatusCode: http.StatusAccepted,
			expectedResponse: Result{
				Message: ResourceDeleted,
			},
		},
		{
			name:               "Deprovisioning Request valid existing tenant",
			method:             http.MethodDelete,
			createCROs:         true,
			existingTenant:     true,
			body:               `{"subscriptionAppName":"` + appName + `","globalAccountGUID":"` + globalAccountId + `","subscribedTenantId":"` + tenantId + `","subscribedSubdomain":"` + subDomain + `"}`,
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
				cat = createCAT(false)
				runtimeObjs = append(runtimeObjs, cat)
			}

			// set custom client for testing
			client, tokenString, err := SetupValidTokenAndIssuerForSubscriptionTests("appname!b14")
			if err != nil {
				t.Fatal(err.Error())
			}
			subHandler := setup(client, runtimeObjs...)

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

			if resType.Tenant != testData.expectedResponse.Tenant && resType.Message != testData.expectedResponse.Message {
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

	type testContextKey string
	const cKey testContextKey = "async-callback-test"
	createCallbackTestServer := func(ctx context.Context, t *testing.T, params *testConfig) *http.Client {
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
				payload := &CallbackResponse{}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("could not read callback request body: %s", err.Error())
				}
				t.Logf("Async callback payload = %s", body)
				err = json.Unmarshal(body, payload)
				if err != nil {
					t.Fatalf("could not parse callback request body: %s", err.Error())
				}
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
					if v := c.Value(cKey); v != nil {
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
		{testName: "1", status: true, useCredentialType: "x509", isProvisioning: true},
		{testName: "2", status: true, useCredentialType: "x509", isProvisioning: false},
		{testName: "3", status: false, useCredentialType: "instance-secret", isProvisioning: true},
		{testName: "4", status: false, useCredentialType: "instance-secret", additionalData: &map[string]any{"foo": "bar"}, isProvisioning: true},
		{testName: "5", status: false, useCredentialType: "x509", additionalData: &map[string]any{"foo1": "bar2", "someKey": &map[string]string{"name": "key", "plan": "none"}}, isProvisioning: true},
	}

	ctx := context.WithValue(context.Background(), cKey, true)
	for _, p := range tests {
		saasData.CredentialType = p.useCredentialType
		t.Run(p.testName, func(t *testing.T) {
			client := createCallbackTestServer(context.TODO(), t, &p)
			subHandler := setup(client)
			subHandler.handleAsyncCallback(
				ctx,
				saasData,
				p.status,
				"/async/callback",
				"https://app.cluster.local",
				p.additionalData,
				p.isProvisioning,
			)
		})
	}
}

func TestCheckTenantStatusContextCancellationAsyncTimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Tenant Status Context Cancellation AsyncTimeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// test context cancellation (like deadline)
		subHandler := setup(nil)
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
	subHandler := setup(nil, cat)
	r := subHandler.checkCAPTenantStatus(context.TODO(), cat.Namespace, cat.Name, true, "")

	if r != true {
		t.Error("expected tenant check to return false")
	}
}

func TestCheckTenantStatusWithCallbacktimeout(t *testing.T) {
	execTestsWithBLI(t, "Check Tenant Status With Callback timeout", []string{"ERP4SMEPREPWORKAPPPLAT-2240"}, func(t *testing.T) {
		// test context cancellation (like deadline)
		cat := createCAT(false)
		subHandler := setup(nil, cat)
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

		subHandler := setup(nil, ca)
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
