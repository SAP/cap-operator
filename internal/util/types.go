/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

type VCAPServiceInstance struct {
	Name         string      `json:"name"` // this attribute holds the binding name if it exists, otherwise, instance name
	BindingGUID  string      `json:"binding_guid,omitempty"`
	BindingName  string      `json:"binding_name,omitempty"`
	InstanceGUID string      `json:"instance_guid,omitempty"`
	InstanceName string      `json:"instance_name,omitempty"`
	Label        string      `json:"label"`
	Plan         string      `json:"plan,omitempty"`
	Credentials  interface{} `json:"credentials"`
	Tags         []string    `json:"tags,omitempty"`
}

type CredentialData struct {
	CredentialType   string `json:"credential-type"`
	ClientId         string `json:"clientid"`
	ClientSecret     string `json:"clientsecret"`
	AuthUrl          string `json:"url"`
	UAADomain        string `json:"uaadomain"`
	ServiceBrokerUrl string `json:"sburl"`
	CertificateUrl   string `json:"certurl"`
	Certificate      string `json:"certificate"`
	CertificateKey   string `json:"key"`
	VerificationKey  string `json:"verificationkey"`
}

type SaasRegistryCredentials struct {
	CredentialData `json:",inline"`
	AppUrls        string `json:"appUrls"`
	SaasManagerUrl string `json:"saas_registry_url"`
}

type SmsCredentials struct {
	CredentialData             `json:",inline"`
	AppUrls                    string `json:"app_urls"`
	SubscriptionManagerUrl     string `json:"subscription_manager_url"`
	CallbackCertificateIssuer  string `json:"callback_certificate_issuer"`
	CallbackCertificateSubject string `json:"callback_certificate_subject"`
}

type XSUAACredentials struct {
	CredentialData        `json:",inline"`
	XSAppName             string `json:"xsappname"`
	TrusterClientIDSuffix string `json:"trustedclientidsuffix"`
}
