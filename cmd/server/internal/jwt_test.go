/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
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
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JWKeys struct {
	Keys []jwk.Key `json:"keys"`
}

type rsaKeyParams struct {
	jwks  *JWKeys
	key   *rsa.PrivateKey
	keyID string
}

const jwksKeyID = "test-key-rsa"
const jwtTestUAADomain = "auth.service.local"
const testSubdomain = "test-subdomain"

const tokenKeysPath = "/token_keys"
const https = "https://"
const brokerApp = "srv-broker!b14"

func createRSAKey() (*rsaKeyParams, error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.PublicKeyOf(privateKey)
	key.Set(jwk.KeyIDKey, jwksKeyID)
	key.Set(jwk.KeyUsageKey, "sig")
	return &rsaKeyParams{
		jwks:  &JWKeys{Keys: []jwk.Key{key}},
		key:   privateKey,
		keyID: jwksKeyID,
	}, nil
}

func SetupValidTokenAndIssuerForSubscriptionTests(xsappname string) (*http.Client, string, error) {
	return setupTokenAndIssuer(&XSUAAConfig{
		UAADomain:      jwtTestUAADomain,
		XSAppName:      xsappname,
		ClientID:       "some-client-id",
		ExpectedScopes: []string{xsappname + ".Callback"},
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
		Scope:           config.ExpectedScopes,
		ClientID:        brokerApp,
		AuthorizedParty: brokerApp,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{config.XSAppName, brokerApp},
			ID:        "jwt-token-01",
			Issuer:    https + strings.Join([]string{testSubdomain, config.UAADomain}, ".") + "/token",
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
		token.Header["jku"] = https + strings.Join([]string{testSubdomain, "foo.bar.local"}, ".") + tokenKeysPath
	} else {
		token.Header["jku"] = https + strings.Join([]string{testSubdomain, config.UAADomain}, ".") + tokenKeysPath
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
	if !rootCAs.AppendCertsFromPEM(certs) {
		return nil, errors.New("could not append CA cert")
	}

	// create test TLS server
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			body, _ = json.Marshal(OpenIDConfig{JWKSURI: https + domain + tokenKeysPath, SigningAlgorithmsSupported: []string{"RS256"}})
		case tokenKeysPath:
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
	ExpectedScopes: []string{"myxsappname.mtcallback"},
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
		ExpectedScopes: testXSUAAConfig.ExpectedScopes,
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

	token, _ := jwt.ParseWithClaims(tokenString, &foo{}, func(t *jwt.Token) (any, error) {
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

func TestVerifyJKUHeader(t *testing.T) {
	const uaaDomain = jwtTestUAADomain
	tests := []struct {
		name     string
		header   map[string]any
		wantHost string
		wantOK   bool
	}{
		{
			name:     "valid jku",
			header:   map[string]any{"jku": https + testSubdomain + "." + uaaDomain + tokenKeysPath},
			wantHost: testSubdomain + "." + uaaDomain,
			wantOK:   true,
		},
		{name: "missing jku header", header: map[string]any{}, wantOK: false},
		{name: "jku header not a string", header: map[string]any{"jku": 123}, wantOK: false},
		{name: "empty jku", header: map[string]any{"jku": ""}, wantOK: false},
		{name: "unparseable jku", header: map[string]any{"jku": "\x7f://x"}, wantOK: false},
		{name: "jku with query params", header: map[string]any{"jku": https + testSubdomain + "." + uaaDomain + tokenKeysPath + "?foo=bar"}, wantOK: false},
		{name: "jku not absolute", header: map[string]any{"jku": testSubdomain + "." + uaaDomain + tokenKeysPath}, wantOK: false},
		{name: "jku with fragment", header: map[string]any{"jku": https + testSubdomain + "." + uaaDomain + tokenKeysPath + "#frag"}, wantOK: false},
		{name: "jku path not token_keys", header: map[string]any{"jku": https + testSubdomain + "." + uaaDomain + "/other"}, wantOK: false},
		{name: "jku host not subdomain of uaa domain", header: map[string]any{"jku": https + testSubdomain + ".foo.bar.local" + tokenKeysPath}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, ok := verifyJKUHeader(&jwt.Token{Header: tt.header}, uaaDomain)
			if ok != tt.wantOK || host != tt.wantHost {
				t.Errorf("verifyJKUHeader() = (%q, %v), want (%q, %v)", host, ok, tt.wantHost, tt.wantOK)
			}
		})
	}
}

func TestAppendWithTrim(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		v    string
		want []string
	}{
		{name: "non-empty value appended", in: []string{"a"}, v: "b", want: []string{"a", "b"}},
		{name: "value trimmed before append", in: []string{"a"}, v: "  b  ", want: []string{"a", "b"}},
		{name: "empty value not appended", in: []string{"a"}, v: "", want: []string{"a"}},
		{name: "whitespace-only value not appended", in: []string{"a"}, v: "   ", want: []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendWithTrim(tt.in, tt.v)
			if len(got) != len(tt.want) {
				t.Fatalf("appendWithTrim() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("appendWithTrim() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestGetOpenIDConfig_Errors(t *testing.T) {
	t.Run("unparseable url", func(t *testing.T) {
		if _, err := getOpenIDConfig("\x7f://x", http.DefaultClient); err == nil {
			t.Error("expected an error for an unparseable URL")
		}
	})

	t.Run("request failure", func(t *testing.T) {
		// nothing is listening on this address, so the GET fails
		if _, err := getOpenIDConfig("https://127.0.0.1:1", http.DefaultClient); err == nil {
			t.Error("expected an error when the request cannot be made")
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		if _, err := getOpenIDConfig(ts.URL, ts.Client()); err == nil {
			t.Error("expected an error for a non-200 response")
		}
	})
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
