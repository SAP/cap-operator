/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"net/http"

	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type SmeV1alpha1Interface interface {
	RESTClient() rest.Interface
	CAPApplicationsGetter
	CAPApplicationVersionsGetter
	CAPTenantsGetter
	CAPTenantOperationsGetter
}

// SmeV1alpha1Client is used to interact with features provided by the sme.sap.com group.
type SmeV1alpha1Client struct {
	restClient rest.Interface
}

func (c *SmeV1alpha1Client) CAPApplications(namespace string) CAPApplicationInterface {
	return newCAPApplications(c, namespace)
}

func (c *SmeV1alpha1Client) CAPApplicationVersions(namespace string) CAPApplicationVersionInterface {
	return newCAPApplicationVersions(c, namespace)
}

func (c *SmeV1alpha1Client) CAPTenants(namespace string) CAPTenantInterface {
	return newCAPTenants(c, namespace)
}

func (c *SmeV1alpha1Client) CAPTenantOperations(namespace string) CAPTenantOperationInterface {
	return newCAPTenantOperations(c, namespace)
}

// NewForConfig creates a new SmeV1alpha1Client for the given config.
// NewForConfig is equivalent to NewForConfigAndClient(c, httpClient),
// where httpClient was generated with rest.HTTPClientFor(c).
func NewForConfig(c *rest.Config) (*SmeV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	httpClient, err := rest.HTTPClientFor(&config)
	if err != nil {
		return nil, err
	}
	return NewForConfigAndClient(&config, httpClient)
}

// NewForConfigAndClient creates a new SmeV1alpha1Client for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*SmeV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientForConfigAndClient(&config, h)
	if err != nil {
		return nil, err
	}
	return &SmeV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new SmeV1alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *SmeV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new SmeV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *SmeV1alpha1Client {
	return &SmeV1alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v1alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *SmeV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
