/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKeys struct {
	Keys []jwk.RSAPublicKey `json:"keys"`
}

type rsaKeyParams struct {
	jwks  *JWKeys
	key   *rsa.PrivateKey
	keyID string
}

const jwksKeyID = "test-key-rsa"
const jwtTestUAADomain = "auth.service.local"
const testSubdomain = "test-subdomain"

func createRSAKey() (*rsaKeyParams, error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.FromRaw(privateKey.PublicKey)
	publicKey := key.(jwk.RSAPublicKey)
	publicKey.Set(jwk.KeyIDKey, jwksKeyID)
	publicKey.Set(jwk.KeyUsageKey, "sig")
	return &rsaKeyParams{
		jwks:  &JWKeys{Keys: []jwk.RSAPublicKey{publicKey}},
		key:   privateKey,
		keyID: jwksKeyID,
	}, nil
}

func SetupValidTokenAndIssuerForSubscriptionTests(xsappname string) (*http.Client, string, error) {
	return setupTokenAndIssuer(&XSUAAConfig{
		UAADomain:      jwtTestUAADomain,
		XSAppName:      xsappname,
		ClientID:       "some-client-id",
		RequiredScopes: []string{xsappname + ".Callback", xsappname + ".mtcallback"},
	}, &jwtTestParameters{})
}

type jwtTestParameters struct {
	invalidJKUHeader      bool
	useDifferentKeyToSign bool
	invalidAudience       bool
	clientIsBroker        bool
	invalidScope          bool
	expiredJWT            bool
	notBeforeInFuture     bool
}

func setupTokenAndIssuer(config *XSUAAConfig, params *jwtTestParameters) (*http.Client, string, error) {
	rsaKey, err := createRSAKey()
	if err != nil {
		return nil, "", fmt.Errorf("error generating rsa key: %s", err.Error())
	}
	claims := XSUAAJWTClaims{
		Scope:           config.RequiredScopes,
		ClientID:        "srv-broker!b14",
		AuthorizedParty: "srv-broker!b14",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{config.XSAppName, "srv-broker!b14"},
			ID:        "jwt-token-01",
			Issuer:    "https://" + strings.Join([]string{testSubdomain, config.UAADomain}, ".") + "/token",
			Subject:   "jwt-token-01",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-30 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	// audience configuration
	if params.invalidAudience {
		claims.Audience = jwt.ClaimStrings{"invalid-a", "invalid-b"}
	} else if params.clientIsBroker {
		claims.ClientID = "sb-d447781d-c010-4c19-af30-ed49097f22de!b446|" + config.XSAppName
		claims.Audience = jwt.ClaimStrings{}
	}

	if params.invalidScope {
		claims.Scope = []string{"scope-a", "scope-b"}
	}

	if params.expiredJWT {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Minute))
	}
	if params.notBeforeInFuture {
		claims.NotBefore = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	if params.invalidJKUHeader {
		token.Header["jku"] = "https://" + strings.Join([]string{testSubdomain, "foo.bar.local"}, ".") + "/token_keys"
	} else {
		token.Header["jku"] = "https://" + strings.Join([]string{testSubdomain, config.UAADomain}, ".") + "/token_keys"
	}

	token.Header["kid"] = rsaKey.keyID

	// sign token
	signKey := rsaKey
	if params.useDifferentKeyToSign {
		signKey, _ = createRSAKey()
	}
	tokenString, err := token.SignedString(signKey.key)
	if err != nil {
		return nil, "", fmt.Errorf("error signing token: %s", err.Error())
	}

	client, err := createJWTTestTLSServer(context.TODO(), rsaKey.jwks)
	if err != nil {
		return nil, "", err
	}

	return client, tokenString, nil
}

func createJWTTestTLSServer(ctx context.Context, jwks *JWKeys) (*http.Client, error) {
	domain := strings.Join([]string{testSubdomain, jwtTestUAADomain}, ".")

	// Append CA cert to the system pool
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certs, err := os.ReadFile("testdata/rootCA.pem")
	if err != nil {
		return nil, err
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, errors.New("could not append CA cert")
	}

	// create test TLS server
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			body, _ = json.Marshal(OpenIDConfig{JWKSURI: "https://" + domain + "/token_keys", SigningAlgorithmsSupported: []string{"RS256"}})
		case "/token_keys":
			body, _ = json.MarshalIndent(jwks, "", "    ")
		}
		w.Write(body)
	}))
	cert, err := tls.LoadX509KeyPair("testdata/auth.service.local.crt", "testdata/auth.service.local.key")
	if err != nil {
		return nil, err
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: rootCAs}
	ts.StartTLS()

	// adjust client to have custom domain resolution
	client := ts.Client()
	client.Transport = &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			if strings.Contains(addr, jwtTestUAADomain+":") {
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
	return client, nil
}

var testXSUAAConfig *XSUAAConfig = &XSUAAConfig{
	UAADomain:      jwtTestUAADomain,
	XSAppName:      "myxsappname",
	ClientID:       "some-client-id",
	RequiredScopes: []string{"myxsappname.Callback", "myxsappname.mtcallback"},
}

func testVerifyValidToken(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err != nil {
		t.Fatal("token validation failed")
	}
}

func testValidTokenWithBrokerClientId(t *testing.T) {
	brokerXSUAAConfig := &XSUAAConfig{
		UAADomain:      testXSUAAConfig.UAADomain,
		ClientID:       testXSUAAConfig.ClientID,
		RequiredScopes: testXSUAAConfig.RequiredScopes,
		XSAppName:      "xsapp!b4711",
	}
	client, tokenString, err := setupTokenAndIssuer(brokerXSUAAConfig, &jwtTestParameters{clientIsBroker: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, brokerXSUAAConfig, client)
	if err != nil {
		t.Fatal("token validation failed")
	}
}

func testInvalidJKUHeader(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{invalidJKUHeader: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}

	if !errors.Is(err, errorJKUTokenHeader) {
		t.Error("error message was not as expected")
	}
}

func testExpiredToken(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{expiredJWT: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Error("error message was not as expected")
	}
}

func testTokenWithNotBefore(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{notBeforeInFuture: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
	if !errors.Is(err, jwt.ErrTokenNotValidYet) {
		t.Error("error message was not as expected")
	}
}

func testInvalidSignature(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{useDifferentKeyToSign: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
}

func testInvalidAudience(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{invalidAudience: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
	if !errors.Is(err, errorInvalidAudience) {
		t.Error("error message was not as expected")
	}
}

func testInvalidScope(t *testing.T) {
	client, tokenString, err := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{invalidScope: true})
	if err != nil {
		t.Fatal(err.Error())
	}

	err = VerifyXSUAAJWTToken(context.TODO(), tokenString, testXSUAAConfig, client)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
	if !errors.Is(err, errorInvalidScope) {
		t.Error("error message was not as expected")
	}
}

func testInvalidClaimsType(t *testing.T) {
	type foo struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	_, tokenString, _ := setupTokenAndIssuer(testXSUAAConfig, &jwtTestParameters{})

	token, _ := jwt.ParseWithClaims(tokenString, &foo{}, func(t *jwt.Token) (interface{}, error) {
		return []byte("Test"), nil
	})

	err := verifyClaims(token, testXSUAAConfig)
	if err == nil {
		t.Fatal("expected token validation to fail")
	}
	if !errors.Is(err, errorInvalidClaimsType) {
		t.Error("error message was not as expected")
	}
}

func TestJWT(t *testing.T) {
	catalog := &[]struct {
		test         func(t *testing.T)
		backlogItems []string
	}{
		{test: testVerifyValidToken, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testValidTokenWithBrokerClientId, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidJKUHeader, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testExpiredToken, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testTokenWithNotBefore, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidSignature, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidAudience, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidScope, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidSignature, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2019", "ERP4SMEPREPWORKAPPPLAT-3188"}},
		{test: testInvalidClaimsType},
	}
	for _, tc := range *catalog {
		nameParts := []string{runtime.FuncForPC(reflect.ValueOf(tc.test).Pointer()).Name()}
		t.Run(strings.Join(append(nameParts, tc.backlogItems...), " "), tc.test)
	}
}
