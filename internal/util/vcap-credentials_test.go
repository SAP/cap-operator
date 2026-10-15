/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func createTestClient(kubeInformerFactory informers.SharedInformerFactory) (*fake.Clientset, error) {
	secs := []k8sruntime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "no-meta-credential-key", Namespace: "default"},
			Data: map[string][]byte{
				"credentials": []byte(`{
						"user": "a-user",
						"password": "some-pass"
					}`),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-with-credential-key", Namespace: "default"},
			Data: map[string][]byte{
				".metadata": []byte(`{
					"metadataProperties": [
						{"name": "instance_name", "sourceName": "service_instance", "format": "text"},
						{"name": "plan", "format": "text"},
						{"name": "type", "format": "text"}
					],
					"credentialProperties": [
						{"name": "credentials", "sourceName": "secret-data", "format": "json", "container": true}
					]
				}`),
				"secret-data": []byte(`{
					"user": "a-user",
					"password": "some-pass"
				}`),
				"service_instance": []byte(`service-a`),
				"plan":             []byte(`default`),
				"type":             []byte(`xyz`),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "malformed-metadata", Namespace: "default"},
			Data: map[string][]byte{
				".metadata": []byte(`{
					"metadataProperties": [
						{"name": "instance_name", "sourceName": "service_instance", "format": "text"},
						{"name": "plan", "format": "text"},
						{"name": "type", "format": "text"}
					],
					"MALFORMED": [[[ //
						{"name": "credentials", "sourceName": "secret-data", "format": "json", "container": true}
					]
				}`),
				"secret-data": []byte(`{
					"user": "a-user",
					"password": "some-pass"
				}`),
				"service_instance": []byte(`service-a`),
				"plan":             []byte(`default`),
				"type":             []byte(`xyz`),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-with-credential-properties", Namespace: "default"},
			Data: map[string][]byte{
				".metadata": []byte(`{
					"metadataProperties": [
						{"name": "instance_name", "sourceName": "service_instance", "format": "text"},
						{"name": "plan", "format": "text"},
						{"name": "type", "format": "text"},
						{"name": "tags", "format": "json"}
					],
					"credentialProperties": [
						{"name": "api-keys", "sourceName": "keys", "format": "json"},
						{"name": "host", "format": "text"}
					]
				}`),
				"secret-data": []byte(`{
					"user": "a-user",
					"password": "some-pass"
				}`),
				"service_instance": []byte(`service-a`),
				"plan":             []byte(`default`),
				"type":             []byte(`xyz`),
				"host":             []byte(`abc.url.local`),
				"keys":             []byte(`["one", "two"]`),
				"tags":             []byte(`["xyz", "lmnop"]`),
			},
		},
	}
	if kubeInformerFactory != nil {
		for _, sec := range secs {
			kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(sec)
		}
	}
	return fake.NewSimpleClientset(secs...), nil
}

func testCreateVCAPEntryFromSecret(t *testing.T) {
	type testCase struct {
		name                 string
		serviceInfo          *v1alpha2.ServiceInfo
		namespace            string
		expectError          bool
		errorMsg             string
		expectedLabel        string
		expectedInstanceName string
		expectTags           bool
	}
	cases := []testCase{
		{
			name:                 "valid credential secret without metadata",
			namespace:            "default",
			serviceInfo:          &v1alpha2.ServiceInfo{Name: "service-a", Secret: "no-meta-credential-key", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
		},
		{
			name:        "secret not found",
			namespace:   "another",
			serviceInfo: &v1alpha2.ServiceInfo{Name: "service-a", Secret: "no-meta-credential-key", Class: "xzy"},
			expectError: true,
			errorMsg:    "secret \"no-meta-credential-key\" not found",
		},
		{
			name:                 "valid credentials (container) with metadata",
			namespace:            "default",
			serviceInfo:          &v1alpha2.ServiceInfo{Name: "service-a", Secret: "metadata-with-credential-key", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
		},
		{
			name:        "malformed metadata",
			namespace:   "default",
			serviceInfo: &v1alpha2.ServiceInfo{Name: "service-a", Secret: "malformed-metadata", Class: "xzy"},
			expectError: true,
			errorMsg:    "could not parse metadata from secret malformed-metadata: invalid character '/' looking for beginning of value",
		},
		{
			name:                 "valid credentials (multiple properties) with metadata",
			namespace:            "default",
			serviceInfo:          &v1alpha2.ServiceInfo{Name: "service-a", Secret: "metadata-with-credential-properties", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
			expectTags:           true,
		},
	}
	kubeInformerFactory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 30*time.Minute)
	c, _ := createTestClient(kubeInformerFactory)
	for i := range cases {
		t.Run(cases[i].name, func(t *testing.T) {
			config := &cases[i]
			entry, err := CreateVCAPEntryFromSecret(config.serviceInfo, config.namespace, c, kubeInformerFactory)
			if err != nil {
				if !config.expectError {
					t.Errorf("unexpected error in test case: %s", config.name)
				}
				if config.errorMsg != "" && err.Error() != config.errorMsg {
					t.Errorf("error '%s' differs from expected for test case: %s", err.Error(), config.name)
				}
				return
			} else {
				if config.expectError {
					t.Errorf("expected error in test case: %s", config.name)
				}
			}
			if config.expectedInstanceName != "" && config.expectedInstanceName != entry["instance_name"].(string) {
				t.Errorf("instance name differs from expected for test case: %s", config.name)
			}
			if tags, ok := entry["tags"]; config.expectTags && (!ok || tags == nil) {
				t.Errorf("expected tags for test case: %s", config.name)
			}
		})
	}
}

func testReadServiceCredentialsFromSecret(t *testing.T) {
	c, _ := createTestClient(nil)

	// test successful read
	secretName := "metadata-with-credential-key"
	credentials, err := ReadServiceCredentialsFromSecret[map[string]string](&v1alpha2.ServiceInfo{Name: "service-a", Class: "xyz", Secret: secretName}, "default", c, false)
	if err != nil {
		t.Errorf("could not read credentials from secret %s", secretName)
	}
	if (*credentials)["user"] != "a-user" || (*credentials)["password"] != "some-pass" {
		t.Errorf("credential attributes from secret %s not as expected", secretName)
	}

	// test with type mismatch
	_, err = ReadServiceCredentialsFromSecret[[]string](&v1alpha2.ServiceInfo{Name: "service-a", Class: "xyz", Secret: secretName}, "default", c, false)
	if err == nil {
		t.Errorf("expected error when reading credentials as array from secret %s", secretName)
	}
}

func TestCreateVCAPEntry_ErrorCases(t *testing.T) {
	si := &v1alpha2.ServiceInfo{Name: "svc", Class: "xsuaa", Secret: "my-secret"}

	// no .metadata and no credentials key
	if _, err := createVCAPEntry(map[string][]byte{"other": []byte("x")}, si); err == nil {
		t.Error("expected error when credentials key is missing")
	}

	// credentials with invalid JSON
	if _, err := createVCAPEntry(map[string][]byte{"credentials": []byte(`{invalid`)}, si); err == nil {
		t.Error("expected error when credentials JSON is invalid")
	}

	// metadata with a json credentialProperty whose source value is invalid JSON
	metaInvalidCred := map[string][]byte{
		".metadata": []byte(`{"credentialProperties":[{"name":"keys","sourceName":"keys","format":"json"}]}`),
		"keys":      []byte(`{invalid`),
	}
	if _, err := createVCAPEntry(metaInvalidCred, si); err == nil {
		t.Error("expected error when credential property JSON is invalid")
	}

	// metadata with a json metadataProperty whose source value is invalid JSON
	metaInvalidMeta := map[string][]byte{
		".metadata": []byte(`{"metadataProperties":[{"name":"tags","sourceName":"tags","format":"json"}]}`),
		"tags":      []byte(`{invalid`),
	}
	if _, err := createVCAPEntry(metaInvalidMeta, si); err == nil {
		t.Error("expected error when metadata property JSON is invalid")
	}
}

func TestCreateVCAPEntryWithMetadata_NameAndLabelFallback(t *testing.T) {
	si := &v1alpha2.ServiceInfo{Name: "svc-fallback", Class: "xsuaa", Secret: "my-secret"}
	// metadata without an instance_name property and without a label -> both fall back to service info
	data := map[string][]byte{
		".metadata": []byte(`{"metadataProperties":[{"name":"plan","format":"text"}],"credentialProperties":[{"name":"user","format":"text"}]}`),
		"plan":      []byte("default"),
		"user":      []byte("a-user"),
	}
	entry, err := createVCAPEntry(data, si)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry["name"] != "svc-fallback" {
		t.Errorf("expected name to fall back to service info name, got: %v", entry["name"])
	}
	if entry["label"] != "xsuaa" {
		t.Errorf("expected label to fall back to service class, got: %v", entry["label"])
	}
}

func TestReadServiceCredentialsFromSecret_Coverage(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cred-secret", Namespace: "default"},
		Data:       map[string][]byte{"credentials": []byte(`{"user":"a-user"}`)},
	})

	// secret not found -> error propagated from CreateVCAPEntryFromSecret
	if _, err := ReadServiceCredentialsFromSecret[map[string]any](&v1alpha2.ServiceInfo{Name: "svc", Secret: "missing", Class: "xsuaa"}, "default", client, false); err == nil {
		t.Error("expected error when secret is not found")
	}

	// withMeta=true -> marshals the full VCAP entry (incl. label/name/tags), not just credentials
	entry, err := ReadServiceCredentialsFromSecret[map[string]any](&v1alpha2.ServiceInfo{Name: "svc", Secret: "cred-secret", Class: "xsuaa"}, "default", client, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if (*entry)["label"] != "xsuaa" {
		t.Errorf("expected label in full VCAP entry, got: %v", (*entry)["label"])
	}
	creds, ok := (*entry)["credentials"].(map[string]any)
	if !ok || creds["user"] != "a-user" {
		t.Errorf("expected credentials.user=a-user, got: %v", (*entry)["credentials"])
	}
}

func TestVCAPCredentials(t *testing.T) {
	catalog := &[]struct {
		test         func(t *testing.T)
		backlogItems []string
	}{
		{test: testCreateVCAPEntryFromSecret, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2611"}},
		{test: testReadServiceCredentialsFromSecret, backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2611"}},
	}
	for _, tc := range *catalog {
		nameParts := []string{runtime.FuncForPC(reflect.ValueOf(tc.test).Pointer()).Name()}
		t.Run(strings.Join(append(nameParts, tc.backlogItems...), " "), tc.test)
	}
}
