/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type XSUAAConfig struct {
	UAADomain string
	// one of xsappname OR clientid must be part of the audience
	XSAppName string
	ClientID  string
	// at least one expected scope must be fulfilled
	ExpectedScopes []string
}

type XSUAAJWTClaims struct {
	Scope                []string `json:"scope"`
	ClientID             string   `json:"client_id"`
	AuthorizedParty      string   `json:"azp"`
	jwt.RegisteredClaims `json:",inline"`
}

type OpenIDConfig struct {
	JWKSURI                    string   `json:"jwks_uri"`
	SigningAlgorithmsSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported            []string `json:"claims_supported"`
}

var (
	errorJKUTokenHeader    = errors.New("jku token header validation failed")
	errorInvalidClaimsType = errors.New("invalid token claims type")
	errorInvalidAudience   = errors.New("invalid token audience")
	errorInvalidScope      = errors.New("invalid token scope")
)

func getOpenIDConfig(uaaURL string, client *http.Client) (*OpenIDConfig, error) {
	url, err := url.Parse(uaaURL)
	if err != nil {
		return nil, err
	}
	url.Path = path.Join(".well-known", "openid-configuration")
	resp, err := client.Get(url.String())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetching openid configuration returned status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	config := OpenIDConfig{}
	return &config, json.Unmarshal(body, &config)
}

// token validation for XSUAA token implemented by following the guidelines provided -> CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
func VerifyXSUAAJWTToken(ctx context.Context, tokenString string, config *XSUAAConfig, client *http.Client) error {
	_, err := jwt.ParseWithClaims(tokenString, &XSUAAJWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		// verify claims excluding expiration (as this is now done internally in jwt v5)
		err := verifyClaims(t, config)
		if err != nil {
			return nil, err
		}

		// verify token algorithm
		if tokenAlg, ok := t.Header["alg"].(string); !ok || tokenAlg == "" {
			return nil, fmt.Errorf("expected token alg to be string")
		}

		// verify JKU header as per XSUAA requirements
		jkuHost, ok := verifyJKUHeader(t, config.UAADomain)
		if !ok {
			return nil, errorJKUTokenHeader
		}

		// get well-known openid configuration
		oidConfig, err := getOpenIDConfig("https://"+jkuHost, client)
		if err != nil {
			return nil, err
		}

		storage, err := jwkset.NewStorageFromHTTP(oidConfig.JWKSURI, jwkset.HTTPClientStorageOptions{Client: client, Ctx: ctx})
		if err != nil {
			return nil, err
		}

		k, err := keyfunc.New(keyfunc.Options{Ctx: ctx, Storage: storage})
		if err != nil {
			return nil, err
		}
		return k.Keyfunc(t)
	}, jwt.WithLeeway(-15*time.Second))

	if err != nil {
		return err
	}

	return nil // all good!
}

func verifyJKUHeader(t *jwt.Token, uaaDomain string) (string, bool) {
	if jku, ok := t.Header["jku"].(string); ok {
		if jku == "" {
			return "", false
		}
		u, err := url.Parse(jku)
		if err != nil {
			return "", false
		}
		if len(u.Query()) > 0 || // there should not be any query parameters
			!u.IsAbs() || // should contain a schema (HTTPS)
			u.Fragment != "" || // should not contain fragments
			!(strings.HasSuffix(u.Path, "token_keys") || strings.HasSuffix(u.Path, "token_keys/")) || // path should end with token_keys
			!strings.HasSuffix(u.Hostname(), uaaDomain) { // jku hostname must be a subdomain of uaa domain
			return "", false
		}

		return u.Host, true
	}
	return "", false
}

func verifyClaims(t *jwt.Token, config *XSUAAConfig) error {
	claims, ok := t.Claims.(*XSUAAJWTClaims)
	if !ok {
		return errorInvalidClaimsType
	}

	// NOTE: in XSUAA scenarios, do not rely on token iss attribute

	// verify audience
	ok = verifyAudience(claims, config)
	if !ok {
		return errorInvalidAudience
	}

	ok = verifyScopes(claims, config)
	if !ok {
		return errorInvalidScope
	}

	return nil
}

func verifyAudience(claims *XSUAAJWTClaims, config *XSUAAConfig) bool {
	tokenAud := convertToMap(extractAudience(claims))
	knownAud := appendWithTrim([]string{config.ClientID}, config.XSAppName) // unless XSAPPNAME is provided, don't add it to valid audience list

	// should match at least one of the expected audience
	for _, expected := range knownAud {
		if _, ok := tokenAud[expected]; ok {
			return true // valid audience
		}

		// additional check for broker clients
		if strings.Contains(expected, "!b") { // is a broker
			for a := range tokenAud {
				if strings.HasSuffix(a, "|"+expected) {
					return true // valid
				}
			}
		}
	}

	return false
}

func extractAudience(claims *XSUAAJWTClaims) []string {
	r := adjustForNamespace(claims.Audience, false)

	// extract audience from client id and scope (XSUAA specific)
	// REFERENCE -> CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/#xsuaa-specifics_1
	if len(r) == 0 {

		r = append(r, adjustForNamespace(claims.Scope, true)...)
	}
	// use client id from token as audience
	r = appendWithTrim(r, claims.ClientID)

	return r
}

func appendWithTrim(s []string, v string) []string {
	if val := strings.TrimSpace(v); len(val) > 0 {
		return append(s, val)
	}
	return s
}

func adjustForNamespace(s []string, ignoreIfNotNamespaced bool) []string {
	r := []string{}
	for _, v := range s {
		if i := strings.Index(v, "."); i > -1 {
			r = appendWithTrim(r, v[:i])
		} else if !ignoreIfNotNamespaced { // when processing scope, add to list only when namespaced
			r = appendWithTrim(r, v)
		}
	}
	return r
}

func verifyScopes(claims *XSUAAJWTClaims, config *XSUAAConfig) bool {
	scope := claims.Scope
	tokenScope := convertToMap(scope)
	for _, expected := range config.ExpectedScopes {
		if _, ok := tokenScope[expected]; ok {
			return true // at least 1 expected scope should match
		}
	}
	return false
}

// Create a dummy lookup map
func convertToMap(s []string) map[string]struct{} {
	if s == nil {
		return nil
	}
	m := map[string]struct{}{}
	for _, item := range s {
		m[item] = struct{}{}
	}
	return m
}
