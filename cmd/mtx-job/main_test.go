/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/sap/cap-operator/internal/util"
)

type testPayload struct {
	Test string `json:"test"`
}

type tlsAttributes struct {
	certificate string
	key         string
}

func readCertificateData() *struct {
	cacert []byte
	cert   []byte
	key    []byte
} {
	cacert, _ := os.ReadFile("../server/internal/testdata/rootCA.pem")
	cert, _ := os.ReadFile("../server/internal/testdata/auth.service.local.crt")
	key, _ := os.ReadFile("../server/internal/testdata/auth.service.local.key")
	return &struct {
		cacert []byte
		cert   []byte
		key    []byte
	}{
		cacert: cacert,
		cert:   cert,
		key:    key,
	}
}

func createTestServer(ctx context.Context, t *testing.T, handler http.HandlerFunc, enableTLS bool, useVCAP bool) (string, func(), error) {
	var (
		tlsInfo   *tlsAttributes = nil
		serverURL string
	)
	// create test server
	ts := httptest.NewUnstartedServer(handler)
	if enableTLS {
		// Append CA cert to the system pool
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certInfo := readCertificateData()
		rootCAs.AppendCertsFromPEM(certInfo.cacert)
		cert, err := tls.X509KeyPair(certInfo.cert, certInfo.key)
		if err != nil {
			return "", nil, err
		}
		ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: rootCAs}
		ts.StartTLS()

		tlsInfo = &tlsAttributes{
			certificate: string(certInfo.cert),
			key:         string(certInfo.key),
		}
		serverURL = ts.Listener.Addr().String()
	} else {
		ts.Start()
		serverURL = ts.URL
	}
	go func() {
		<-ctx.Done()
		ts.Close()
	}()

	basePath, err := createCredentialsForTesting(ts.URL, tlsInfo, useVCAP)
	return serverURL, func() {
		if !useVCAP {
			os.RemoveAll(basePath)
		} else {
			os.Unsetenv(EnvVCAPServices)
		}
	}, err
}

func createCredentialsForTesting(url string, tls *tlsAttributes, useVCAP bool) (string, error) {
	instance := "test-uaa"
	os.Setenv(EnvXSUAAInstanceName, instance)

	files := map[string]string{
		"clientid":        "xsuaa-client-id",
		"clientsecret":    "xsuaa-secret",
		"url":             url,
		"credential-type": "instance-secret",
		"certurl":         "https://cert.auth.service.local",
	}
	if tls != nil {
		files["credential-type"] = "x509"
		files["certificate"] = tls.certificate
		files["key"] = tls.key
	}

	if useVCAP {
		vcap := map[string][]util.VCAPServiceInstance{"xsuaa": {{
			Name:         instance,
			InstanceName: instance,
			Label:        "xsuaa",
			Tags:         []string{"xsuaa"},
			Credentials:  files,
		}}}
		data, _ := json.Marshal(vcap)
		os.Setenv(EnvVCAPServices, string(data))
		return "", nil
	}

	basePath, err := os.MkdirTemp("", "test-*")
	if err != nil {
		return "", fmt.Errorf("could not create temp dir: %s", err.Error())
	}
	os.Setenv(EnvCredentialsPath, basePath)

	tmpDir := path.Join(basePath, "xsuaa", instance)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("could not create temp dir: %s", err.Error())
	}
	var createAttributeFile = func(ch chan<- error, file string, value string) {
		ch <- os.WriteFile(path.Join(tmpDir, file), []byte(value), 0755)
	}

	ch := make(chan error, len(files))
	for k, v := range files {
		go createAttributeFile(ch, k, v)
	}
	for i := 0; i < len(files); i++ {
		err := <-ch
		if err != nil {
			return "", fmt.Errorf("could not create temp file")
		}
	}

	return basePath, nil
}

func TestWaitForMTX(t *testing.T) {
	ready, timeout := false, false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mtx/v1/provisioning/tenant" {
			t.Error("wrong URI path")
		}
		if ready && !timeout {
			body, _ := json.Marshal([]string{"t1", "t2"})
			w.Write(body)
		} else {
			ready = true
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()
	mtxURL, _ := url.Parse(ts.URL)
	token := &OAuthResponse{AccessToken: "sample-access-token", TokenType: "bearer"}

	// test with one iteration expecting error and the next successful
	err := waitForMTX(mtxURL, http.Client{}, token)
	if err != nil {
		t.Error("unexpected error")
	}

	// test timeout
	timeout = true
	os.Setenv(EnvWaitForMTXTimeoutSeconds, "2")
	err = waitForMTX(mtxURL, http.Client{}, token)
	if err == nil {
		t.Error("expected context deadline error")
	} else {
		if err.Error() != "error when waiting for mtx: context deadline exceeded" {
			t.Errorf("wrong error: %s", err.Error())
		}
	}
}

func TestFetchOAuthTokenWithClientSecret(t *testing.T) {
	var unauthorized bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Error("expected POST operation")
		}
		if r.Header.Get(ContentType) != ContentFormEncoded {
			t.Errorf("expected %s %s", ContentType, ContentFormEncoded)
		}
		if r.Header.Get(Authorization) != fmt.Sprintf("Basic %s", base64.URLEncoding.EncodeToString([]byte("xsuaa-client-id:xsuaa-secret"))) {
			t.Errorf("incorrect authorization header")
		}
		if !unauthorized {
			w.Write([]byte("{\"access_token\":\"sample-access-token\",\"token_type\":\"bearer\",\"expires_in\":43199}"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}

	_, tearDown, err := createTestServer(context.TODO(), t, handler, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}
	defer tearDown()

	// test valid request
	token, err := fetchOAuthToken(http.Client{})
	if err != nil {
		t.Fatal(err.Error())
	}
	if token.TokenType != "bearer" || token.AccessToken != "sample-access-token" {
		t.Error("unexpected response body")
	}

	// test unauthorized
	unauthorized = true
	_, err = fetchOAuthToken(http.Client{})
	if err == nil {
		t.Error("expected error")
	}
}

func TestFetchOAuthTokenWithX509Cert(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Error("expected POST operation")
		}
		if r.Header.Get(ContentType) != ContentFormEncoded {
			t.Errorf("expected %s %s", ContentType, ContentFormEncoded)
		}
		w.Write([]byte("{\"access_token\":\"sample-access-token\",\"token_type\":\"bearer\",\"expires_in\":43199}"))
	}

	type testConfig struct {
		testCase string
		useVCAP  bool
	}

	for _, p := range []testConfig{
		{testCase: "fetch token using x509 certificate using credentials from volume", useVCAP: false},
		{testCase: "fetch token using x509 certificate using credentials from VCAP_SERVICES", useVCAP: true},
	} {
		t.Run(p.testCase, func(t *testing.T) {
			serverAddr, tearDown, err := createTestServer(context.TODO(), t, handler, true, p.useVCAP)
			if err != nil {
				t.Fatal(err.Error())
			}
			defer tearDown()

			dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.Contains(addr, "auth.service.local:") {
					addr = serverAddr
				}
				return net.Dial(network, addr)
			}
			client := http.Client{}
			if t, ok := client.Transport.(*http.Transport); ok {
				t.DialContext = dial
			} else {
				client.Transport = &http.Transport{DialContext: dial}
			}

			// test valid request
			token, err := fetchOAuthToken(client)
			if err != nil {
				t.Fatal(err.Error())
			}
			if token.TokenType != "bearer" || token.AccessToken != "sample-access-token" {
				t.Error("unexpected response body")
			}
		})
	}
}

func TestSubscription(t *testing.T) {
	mtx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mtx/v1/provisioning/tenant/test-tenant-id" {
			t.Errorf("expected route with tenant id test-tenant-id")
		}
		if r.Header.Get(ContentType) != ContentAppJson {
			t.Errorf("expected %s %s", ContentType, ContentAppJson)
		}
		if r.Header.Get(Authorization) != "Bearer sample-token" {
			t.Error("expected oauth token for authorization")
		}
		content, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("could not read payload: %s", err.Error())
		}
		var p testPayload
		err = json.Unmarshal(content, &p)
		if err != nil {
			t.Errorf("could not read payload: %s", err.Error())
		}
		switch p.Test {
		case "provisioning-ok":
			if r.Method != http.MethodPut {
				t.Errorf("expected %s", http.MethodPut)
			}
			w.WriteHeader(http.StatusOK)
		case "provisioning-fail":
			w.WriteHeader(http.StatusBadRequest)
		case "deprovisioning-ok":
			if r.Method != http.MethodDelete {
				t.Errorf("expected %s", http.MethodDelete)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Error("unknown test payload")
		}
	}))
	defer mtx.Close()
	mtxURL, _ := url.Parse(mtx.URL)
	os.Setenv(EnvMTXTenantId, "test-tenant-id")

	os.Setenv(EnvMTXRequestType, RequestTypeProvisioning)
	os.Setenv(EnvMTXPayload, "{\"test\":\"provisioning-ok\"}")
	err := processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	os.Setenv(EnvMTXPayload, "{\"test\":\"provisioning-fail\"}")
	err = processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err == nil {
		t.Errorf("expected error")
	}

	os.Setenv(EnvMTXRequestType, RequestTypeDeprovisioning)
	os.Setenv(EnvMTXPayload, "{\"test\":\"deprovisioning-ok\"}")
	err = processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestUpgrade(t *testing.T) {
	jobPreviousStatus := ""
	mtx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(Authorization) != "Bearer sample-token" {
			t.Error("expected oauth token for authorization")
		}

		switch r.URL.Path {
		case "/mtx/v1/model/asyncUpgrade":
			if r.Method != http.MethodPost {
				t.Errorf("expected %s", http.MethodPost)
			}
			jobPreviousStatus = ""
			if r.Header.Get(ContentType) != ContentAppJson {
				t.Errorf("expected %s %s", ContentType, ContentAppJson)
			}
			content, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("could not read payload: %s", err.Error())
			}
			var p testPayload
			err = json.Unmarshal(content, &p)
			if err != nil {
				t.Errorf("could not read payload: %s", err.Error())
			}
			switch p.Test {
			case "upgrade-job-ok":
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("{\"jobID\":\"job-id-ok\"}"))
			case "upgrade-job-fail":
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("{\"jobID\":\"job-id-fail\"}"))
			case "upgrade-job-queue-tenant-fail":
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("{\"jobID\":\"job-id-queue-fail\"}"))
			case "upgrade-fail":
				w.WriteHeader(http.StatusInternalServerError)
			}
		case "/mtx/v1/model/status/job-id-ok":
			if r.Method != http.MethodGet {
				t.Errorf("expected %s", http.MethodGet)
			}
			jobResponse := upgradeJobResponse{Status: "FINISHED", Result: upgradeJobResult{Tenants: map[string]tenantUpgradeResult{"test-tenant-id": {Status: "SUCCESS"}}}}
			body, _ := json.Marshal(jobResponse)
			w.Write(body)
		case "/mtx/v1/model/status/job-id-fail":
			if r.Method != http.MethodGet {
				t.Errorf("expected %s", http.MethodGet)
			}
			jobResponse := upgradeJobResponse{Status: "FAILED", Error: "memory dump"}
			body, _ := json.Marshal(jobResponse)
			w.Write(body)
		case "/mtx/v1/model/status/job-id-queue-fail":
			if r.Method != http.MethodGet {
				t.Errorf("expected %s", http.MethodGet)
			}
			var jobResponse upgradeJobResponse
			if jobPreviousStatus == "" {
				jobResponse = upgradeJobResponse{Status: "QUEUED"}
				jobPreviousStatus = "QUEUED"
			} else {
				jobResponse = upgradeJobResponse{Status: "FINISHED", Result: upgradeJobResult{Tenants: map[string]tenantUpgradeResult{"test-tenant-id": {Status: "FAILED", Message: "tenant upgrade failed"}}}}
			}
			body, _ := json.Marshal(jobResponse)
			w.Write(body)
		}
	}))
	defer mtx.Close()
	mtxURL, _ := url.Parse(mtx.URL)
	os.Setenv(EnvMTXRequestType, RequestTypeUpgrade)
	os.Setenv(EnvMTXTenantId, "test-tenant-id")

	os.Setenv(EnvMTXPayload, "{\"test\":\"upgrade-job-ok\"}")
	err := processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	os.Setenv(EnvMTXPayload, "{\"test\":\"upgrade-fail\"}")
	err = processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err == nil {
		t.Errorf("expected error")
	}

	os.Setenv(EnvMTXPayload, "{\"test\":\"upgrade-job-fail\"}")
	err = processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err == nil {
		t.Errorf("expected error")
	}

	os.Setenv(EnvMTXPayload, "{\"test\":\"upgrade-job-queue-tenant-fail\"}")
	err = processRequest(mtxURL, http.Client{}, &OAuthResponse{AccessToken: "sample-token", TokenType: "bearer"})
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestExecute(t *testing.T) {
	provisioningError, mtxTimeout := false, false
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Write([]byte("{\"access_token\":\"sample-access-token\",\"token_type\":\"bearer\",\"expires_in\":43199}"))
		case "/mtx/v1/provisioning/tenant":
			if mtxTimeout {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				w.Write([]byte("[]"))
			}
		case "/mtx/v1/provisioning/tenant/test-tenant-id":
			if provisioningError {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		}
	}

	serverURL, tearDown, err := createTestServer(context.TODO(), t, handler, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}
	defer tearDown()

	// test w/o mtx url
	os.Unsetenv(EnvMTXServiceURL)
	code := execute()
	if code != 1 {
		t.Error("expected error")
	}

	// test w/o request type
	provisioningError = true
	os.Setenv(EnvMTXServiceURL, serverURL)
	os.Unsetenv(EnvMTXRequestType)
	code = execute()
	if code != 1 {
		t.Error("expected error")
	}

	// test with successful simulated provisioning
	provisioningError = false
	os.Setenv(EnvMTXTenantId, "test-tenant-id")
	os.Setenv(EnvMTXPayload, "{}")
	os.Setenv(EnvMTXRequestType, RequestTypeProvisioning)
	code = execute()
	if code != 0 {
		t.Error("expected exit code 0")
	}

	// test timeout waiting for mtx
	mtxTimeout = true
	os.Setenv(EnvMTXServiceURL, serverURL)
	os.Setenv(EnvWaitForMTXTimeoutSeconds, "2")
	code = execute()
	if code != 1 {
		t.Error("expected error")
	}
}
