/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// See Kubernetes-Service-Bindings/doc
type SecretMetadata struct {
	MetadataProperties   []MetadataPropertyDescriptor `json:"metaDataProperties"`
	CredentialProperties []MetadataPropertyDescriptor `json:"credentialProperties"`
}

type MetadataPropertyDescriptor struct {
	Name       string         `json:"name"`
	SourceName string         `json:"sourceName"`
	Format     PropertyFormat `json:"format"`
	Container  bool           `json:"container"`
}

func (d MetadataPropertyDescriptor) getKey() (key string) {
	key = d.SourceName
	if key == "" {
		key = d.Name
	}
	return
}

func (d MetadataPropertyDescriptor) move(source map[string][]byte, target map[string]any) (map[string]any, error) {
	key := d.getKey()
	switch d.Format {
	case PropertyFormatText:
		target[d.Name] = string(source[key]) // when property is a container, it cannot have text format
	case PropertyFormatJSON:
		var (
			v   *any
			err error
		)
		if v, err = ParseJSON[any](source[key]); err != nil {
			return nil, err
		}
		if d.Container {
			return (*v).(map[string]any), nil
		}
		target[d.Name] = v
	}
	return target, nil
}

type PropertyFormat string

const (
	PropertyFormatText PropertyFormat = "text"
	PropertyFormatJSON PropertyFormat = "json"
)

func ReadServiceCredentialsFromSecret[T any](serviceInfo *v1alpha1.ServiceInfo, ns string, kubeClient kubernetes.Interface) (*T, error) {
	entry, err := CreateVCAPEntryFromSecret(serviceInfo, ns, kubeClient)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(entry["credentials"])
	if err != nil {
		return nil, fmt.Errorf("could not serialize credentials for service %s: %s", serviceInfo.Name, err)
	}
	return ParseJSON[T](b)
}

func CreateVCAPEntryFromSecret(serviceInfo *v1alpha1.ServiceInfo, ns string, kubeClient kubernetes.Interface) (entry map[string]any, err error) {
	// Get secret
	secret, err := kubeClient.CoreV1().Secrets(ns).Get(context.TODO(), serviceInfo.Secret, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return createVCAPEntry(secret.Data, serviceInfo)
}

func createVCAPEntry(data map[string][]byte, si *v1alpha1.ServiceInfo) (entry map[string]any, err error) {
	if metaBytes, ok := data[".metadata"]; ok { // metadata available from new service binding specification
		var meta SecretMetadata
		if err = json.Unmarshal(metaBytes, &meta); err != nil {
			return nil, errorCredentialParse("metadata", si.Secret, err)
		}
		return createVCAPEntryWithMetadata(data, &meta, si)
	} else { // fallback to reading secret-key "credentials"
		credBytes, ok := data["credentials"]
		if !ok {
			return nil, fmt.Errorf("could not find credentials for secret %s", si.Secret)
		}
		// Parse JSON value for the given service secret
		cred, err := ParseJSON[map[string]any](credBytes)
		if err != nil {
			return nil, errorCredentialParse("credentials", si.Secret, err)
		}
		entry = map[string]any{
			"credentials":   cred,
			"label":         si.Class,
			"name":          si.Name,
			"instance_name": si.Name,
			"tags":          []string{si.Class}, // app-router looks for xsuaa in tags alone! So add class as a tag!
		}
	}
	return
}

func createVCAPEntryWithMetadata(data map[string][]byte, meta *SecretMetadata, si *v1alpha1.ServiceInfo) (entry map[string]any, err error) {
	entry = map[string]any{"credentials": map[string]any{}}
	for i := range meta.MetadataProperties {
		if entry, err = meta.MetadataProperties[i].move(data, entry); err != nil {
			return nil, errorCredentialParse("metadata", si.Secret, err)
		}
	}
	for i := range meta.CredentialProperties {
		if entry["credentials"], err = meta.CredentialProperties[i].move(data, entry["credentials"].(map[string]any)); err != nil {
			return nil, errorCredentialParse("credentials", si.Secret, err)
		}
		if meta.CredentialProperties[i].Container {
			break
		}
	}
	if _, ok := entry["label"]; !ok {
		entry["label"] = si.Class // ensure label is provided
	}
	// ensure name is set
	if instanceName, ok := entry["instance_name"]; ok {
		entry["name"] = instanceName // conform to VCAP_SERVICES specification (https://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html#VCAP-SERVICES)
	} else {
		entry["name"] = si.Name // source from service info as a fallback
	}
	return
}

func errorCredentialParse(key string, secret string, err error) error {
	return fmt.Errorf("could not parse %s from secret %s: %w", key, secret, err)
}

func ParseJSON[T any](b []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err // ensure nil pointer is returned in case of error
	}
	return &v, nil
}
