/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"k8s.io/klog/v2"
)

const (
	EnvXSUAAInstanceName        = "XSUAA_INSTANCE_NAME"
	EnvMTXServiceURL            = "MTX_SERVICE_URL"
	EnvMTXRequestType           = "MTX_REQUEST_TYPE"
	EnvMTXTenantId              = "MTX_TENANT_ID"
	EnvMTXPayload               = "MTX_REQUEST_PAYLOAD"
	EnvCredentialsPath          = "CREDENTIALS_FILE_PATH"
	EnvWaitForMTXTimeoutSeconds = "WAIT_FOR_MTX_TIMEOUT_SECONDS"
	EnvVCAPServices             = "VCAP_SERVICES"
)

const (
	RequestTypeProvisioning   = "provisioning"
	RequestTypeDeprovisioning = "deprovisioning"
	RequestTypeUpgrade        = "upgrade"
)

const (
	Authorization      = "Authorization"
	Bearer             = "Bearer"
	ContentType        = "Content-Type"
	ContentAppJson     = "application/json"
	ContentFormEncoded = "application/x-www-form-urlencoded"
	ServiceClassXSUAA  = "xsuaa"
)

const (
	ErrorKillingProcess = "Error killing process"
	FailedWith          = "failed with"
)

const (
	statusQueued  = "QUEUED"
	statusRunning = "RUNNING"
	statusFailed  = "FAILED"
	statusSuccess = "SUCCESS"
)

type asyncUpgradeResponse struct {
	JobId string `json:"jobID"`
}

type upgradeJobResponse struct {
	Error  string           `json:"error"`
	Status string           `json:"status"`
	Result upgradeJobResult `json:"result"`
}

type upgradeJobResult struct {
	Tenants map[string]tenantUpgradeResult `json:"tenants"`
}

type tenantUpgradeResult struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	BuildLogs string `json:"buildLogs"`
}

func fetchXSUAAServiceCredentials() (*util.XSUAACredentials, error) {
	vcap, ok := os.LookupEnv(EnvVCAPServices)
	if !ok || vcap == "" {
		return fetchXSUAAServiceCredentialsFromVolume()
	}
	return fetchXSUAAServiceCredentialsFromVCAP()
}

func fetchXSUAAServiceCredentialsFromVCAP() (*util.XSUAACredentials, error) {
	serviceInstanceName := os.Getenv(EnvXSUAAInstanceName)
	raw := os.Getenv(EnvVCAPServices)
	if raw == "" {
		return nil, fmt.Errorf("could not read %s from environment", EnvVCAPServices)
	}
	var parsed map[string][]util.VCAPServiceInstance
	err := json.Unmarshal([]byte(raw), &parsed)
	if err != nil {
		return nil, fmt.Errorf("error parsing VCAP_SERVICES: %s", err.Error())
	}
	instances := parsed[ServiceClassXSUAA]
	if len(instances) == 0 {
		return nil, fmt.Errorf("could not find instances of service offering %s", ServiceClassXSUAA)
	}
	for _, i := range instances {
		name := i.Name
		if i.BindingName != "" { // if binding name is provided, use explicit instance name
			if i.InstanceName == "" {
				continue // instance name could not be identified
			}
			name = i.InstanceName
		}
		if name == serviceInstanceName {
			return parseXSUAACredentials(i.Credentials)
		}
	}

	return nil, fmt.Errorf("credentials for service instance %s not found", serviceInstanceName)
}

func parseXSUAACredentials(data interface{}) (credentials *util.XSUAACredentials, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("could parse credentials for service %s: %s", ServiceClassXSUAA, err.Error())
		}
	}()
	creds, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var xsuaaCredentials util.XSUAACredentials
	err = json.Unmarshal(creds, &xsuaaCredentials)
	if err != nil {
		return nil, err
	}
	return &xsuaaCredentials, nil
}

func fetchXSUAAServiceCredentialsFromVolume() (*util.XSUAACredentials, error) {
	instance := os.Getenv(EnvXSUAAInstanceName)
	credPath := getXSUAACredentialsPath(instance)
	readAttribute := func(attribute string) (string, error) {
		data, err := os.ReadFile(path.Join(credPath, attribute))
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	var err error
	parameters := &util.XSUAACredentials{}
	parameters.CredentialType, err = readAttribute("credential-type")
	if err != nil {
		return nil, err
	}
	parameters.AuthUrl, err = readAttribute("url")
	if err != nil {
		return nil, err
	}
	parameters.ClientId, err = readAttribute("clientid")
	if err != nil {
		return nil, err
	}
	if parameters.CredentialType == "x509" {
		parameters.CertificateUrl, err = readAttribute("certurl")
		if err != nil {
			return nil, err
		}
		parameters.Certificate, err = readAttribute("certificate")
		if err != nil {
			return nil, err
		}
		parameters.CertificateKey, err = readAttribute("key")
		if err != nil {
			return nil, err
		}
	} else {
		parameters.ClientSecret, err = readAttribute("clientsecret")
		if err != nil {
			return nil, err
		}
	}

	return parameters, nil
}

func getXSUAACredentialsPath(instance string) string {
	basePath, ok := os.LookupEnv(EnvCredentialsPath)
	if !ok {
		basePath = "/etc/secrets/sapcp"
	}
	return path.Join(basePath, ServiceClassXSUAA, instance)
}

type OAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // bearer
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	JTI         string `json:"jti"`
}

func main() {
	klog.SetLogger(util.GetLogger())
	os.Exit(execute())
}

func execute() int {
	var (
		err    error // main error used for control flow
		mtxURL *url.URL
		token  *OAuthResponse
		client http.Client = http.Client{Timeout: time.Duration(5 * time.Second)}
	)

	defer func() {
		// terminate mtx sidecar via tcp connect when completed
		terminateMTXSidecar()

		// log final error, if any
		if err != nil {
			klog.ErrorS(err, "Aborting with error")
		}
	}()

	if token, err = fetchOAuthToken(client); err != nil {
		return 1
	}

	if mtxURLEnv, ok := os.LookupEnv(EnvMTXServiceURL); ok {
		mtxURL, err = url.Parse(mtxURLEnv)
	} else {
		err = errors.New("could not identify mtx service URL from environment")
		return 1
	}

	// wait for mtx instance by checking available tenants
	if err = waitForMTX(mtxURL, client, token); err != nil {
		return 1
	}

	// process request
	if err = processRequest(mtxURL, client, token); err != nil {
		return 1
	}

	return 0
}

func terminateMTXSidecar() {
	klog.InfoS("Terminating by TCP connect..")
	// TODO: make port configurable
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		klog.ErrorS(err, "Error during mtx termination")
	}
	if conn != nil {
		conn.Close()
		klog.InfoS("Terminated..")
	}
}

func waitForMTX(mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	t, ok := os.LookupEnv(EnvWaitForMTXTimeoutSeconds)
	if !ok || t == "" {
		t = "300" // default wait period of 5 minutes
	}
	d, err := time.ParseDuration(t + "s")
	if err != nil {
		return fmt.Errorf("error parsing wait duration: %s", err.Error())
	}

	wait, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	for {
		select {
		case <-wait.Done():
			return fmt.Errorf("error when waiting for mtx: %s", wait.Err().Error())
		default:
			err := getTenants(mtxURL, client, token)
			if err == nil {
				return nil
			}
			klog.Warningf("waiting for mtx: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
}

func getTenants(mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	mtxURL.Path = path.Join("mtx", "v1/provisioning/tenant")

	req, err := http.NewRequest("GET", mtxURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set(Authorization, fmt.Sprintf("%s %s", Bearer, token.AccessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		klog.InfoS("Response from "+mtxURL.Path, v1alpha1.CAPTenantResource, body)
		return nil
	} else {
		return fmt.Errorf("mtx returned status %s", resp.Status)
	}
}

func fetchOAuthToken(client http.Client) (*OAuthResponse, error) {
	parameters, err := fetchXSUAAServiceCredentials()
	if err != nil {
		return nil, fmt.Errorf("error when reading xsuaa credentials: %w", err)
	}

	var req *http.Request
	if parameters.CredentialType == "x509" {
		req, err = createRequestWithX509Certificate(parameters, &client)
		// reset client tls config
		defer func() { client.Transport = &http.Transport{} }()
	} else {
		req, err = createRequestWithClientCredentials(parameters)
	}
	if err != nil {
		return nil, fmt.Errorf("error preparing token request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error during http call: status %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var token OAuthResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, fmt.Errorf("could not parse oauth response: %w", err)
	} else {
		klog.InfoS("retrieved token", "scope", token.Scope)
	}

	return &token, nil
}

func prepareTokenRequest(clientID string, tokenURL string) (*http.Request, error) {
	data := url.Values{}
	data.Add("client_id", clientID)
	data.Add("grant_type", "client_credentials")
	req, err := http.NewRequest(http.MethodPost, tokenURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error when creating request: %w", err)
	}
	req.Header.Set(ContentType, ContentFormEncoded)
	return req, nil
}

func createRequestWithClientCredentials(parameters *util.XSUAACredentials) (*http.Request, error) {
	req, err := prepareTokenRequest(parameters.ClientId, parameters.AuthUrl)
	if err != nil {
		return nil, err
	}
	req.Header.Set(Authorization, "Basic "+base64.URLEncoding.EncodeToString([]byte(parameters.ClientId+":"+parameters.ClientSecret)))
	return req, nil
}

func createRequestWithX509Certificate(parameters *util.XSUAACredentials, client *http.Client) (*http.Request, error) {
	// Read the key pair to create certificate
	cert, err := tls.X509KeyPair([]byte(parameters.Certificate), []byte(parameters.CertificateKey))
	if err != nil {
		return nil, err
	}

	// Use system certificate pool and add add certificate to it
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	caCertPool.AppendCertsFromPEM([]byte(parameters.Certificate))

	// setup TLS configuration for client
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
	if t, ok := client.Transport.(*http.Transport); ok {
		t.TLSClientConfig = tlsConfig
	} else {
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	return prepareTokenRequest(parameters.ClientId, parameters.CertificateUrl)
}

func processRequest(mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	switch os.Getenv(EnvMTXRequestType) {
	case RequestTypeProvisioning:
		return processSubscription(RequestTypeProvisioning, mtxURL, client, token)
	case RequestTypeDeprovisioning:
		return processSubscription(RequestTypeDeprovisioning, mtxURL, client, token)
	case RequestTypeUpgrade:
		return processUpgrade(mtxURL, client, token)
	default:
		return errors.New("unknown mtx request type")
	}
}

func processSubscription(requestType string, mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	tenantId := os.Getenv(EnvMTXTenantId)

	client.Timeout = 10 * time.Minute
	mtxURL.Path = path.Join("mtx", "v1/provisioning/tenant", tenantId)
	reqBody := bytes.NewBufferString(os.Getenv(EnvMTXPayload))
	var (
		req *http.Request
		err error
	)
	if requestType == RequestTypeProvisioning {
		req, err = http.NewRequest("PUT", mtxURL.String(), reqBody)
	} else {
		req, err = http.NewRequest("DELETE", mtxURL.String(), reqBody)
	}
	if err != nil {
		return fmt.Errorf("error when creating request for %s: %w", requestType, err)
	}
	req.Header.Set(ContentType, ContentAppJson)
	req.Header.Set(Authorization, fmt.Sprintf("%s %s", Bearer, token.AccessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	klog.InfoS("Response received from mtx", "tenant id", tenantId, "type", requestType, "http status code", resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else {
		return fmt.Errorf("%s for %s %s %s: %d", requestType, v1alpha1.CAPTenantKind, tenantId, FailedWith, resp.StatusCode)
	}
}

func processUpgrade(mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	tenantId := os.Getenv(EnvMTXTenantId)
	client.Timeout = 10 * time.Minute
	mtxURL.Path = "mtx/v1/model/asyncUpgrade"
	reqBody := bytes.NewBufferString(os.Getenv(EnvMTXPayload))

	req, err := http.NewRequest("POST", mtxURL.String(), reqBody)

	if err != nil {
		return fmt.Errorf("error when creating request for upgrade: %v", err)
	}
	req.Header.Set(ContentType, ContentAppJson)
	req.Header.Set(Authorization, fmt.Sprintf("%s %s", Bearer, token.AccessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	klog.InfoS("Response received from mtx", "tenant id", tenantId, "type", "upgrade", "http status code", resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		decoder := json.NewDecoder(resp.Body)
		defer resp.Body.Close()
		var asyncUpgradeResp asyncUpgradeResponse
		err = decoder.Decode(&asyncUpgradeResp)
		if err != nil {
			klog.ErrorS(err, "Error parsing response for async upgrade")
			return err
		}
		// Check the final job status
		return checkJobStatus(asyncUpgradeResp.JobId, tenantId, mtxURL, client, token)

	} else {
		return fmt.Errorf("upgrade for %s %s %s: %d", v1alpha1.CAPTenantKind, tenantId, FailedWith, resp.StatusCode)
	}
}

func checkJobStatus(jobId string, tenantId string, mtxURL *url.URL, client http.Client, token *OAuthResponse) error {
	// Create Request for fetching mtx upgrade Job status
	mtxURL.Path = "/mtx/v1/model/status/" + jobId
	req, err := http.NewRequest("GET", mtxURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error when creating request for %s(%s) upgrade job status: %w", v1alpha1.CAPTenantKind, tenantId, err)
	}
	req.Header.Set(ContentType, ContentAppJson)
	req.Header.Set(Authorization, fmt.Sprintf("%s %s", Bearer, token.AccessToken))
	// wait until the final status of Upgrade job is received
	success, err := fetchJobStatus(tenantId, client, req)
	if err != nil || !success {
		return fmt.Errorf("upgrade job for %s: %s %s: %w", v1alpha1.CAPTenantKind, tenantId, FailedWith, err)
	}
	// Upgrade Job was Successful
	return nil
}

// Wait for and check mtx upgrade job result until a final status is received
func fetchJobStatus(tenantId string, client http.Client, req *http.Request) (bool, error) {
	// Send the Get Request to fetch mtx asyncUpgrade Job status
	jobResp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	// Parse the respnose
	decoder := json.NewDecoder(jobResp.Body)
	defer jobResp.Body.Close()
	var upgradeJobResp upgradeJobResponse
	err = decoder.Decode(&upgradeJobResp)
	if err != nil {
		klog.ErrorS(err, "Parsing response failed for async upgrade", v1alpha1.CAPTenantKind, tenantId, FailedWith, err)
		return false, err
	}
	// Re-trigger after sleeping for 10s if status is not "FINISHED"
	// TODO: check if some of these should be moved to own go routines
	if upgradeJobResp.Status == statusQueued || upgradeJobResp.Status == statusRunning {
		time.Sleep(10 * time.Second)
		return fetchJobStatus(tenantId, client, req)
	} else if upgradeJobResp.Status == statusFailed {
		// Job Failure
		return false, fmt.Errorf("aync upgrade job for %s: %s %s: %s", v1alpha1.CAPTenantKind, tenantId, FailedWith, upgradeJobResp.Error)
	}

	// Check tenant upgrade status for the current tenant and return error if needed
	if upgradeJobResp.Result.Tenants[tenantId].Status != statusSuccess {
		return false, fmt.Errorf("upgrade of %s: %s %s: %s", v1alpha1.CAPTenantKind, tenantId, FailedWith, upgradeJobResp.Result.Tenants[tenantId].Message)
	}
	// tenant upgrade was successful
	klog.InfoS("upgrade successful!", "tenant id", tenantId)
	return true, nil
}
