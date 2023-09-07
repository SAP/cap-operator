/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func createTestClient() (*fake.Clientset, error) {
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
	return fake.NewSimpleClientset(secs...), nil
}

func testCreateVCAPEntryFromSecret(t *testing.T) {
	type testCase struct {
		name                 string
		serviceInfo          *v1alpha1.ServiceInfo
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
			serviceInfo:          &v1alpha1.ServiceInfo{Name: "service-a", Secret: "no-meta-credential-key", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
		},
		{
			name:        "secret not found",
			namespace:   "another",
			serviceInfo: &v1alpha1.ServiceInfo{Name: "service-a", Secret: "no-meta-credential-key", Class: "xzy"},
			expectError: true,
			errorMsg:    "secrets \"no-meta-credential-key\" not found",
		},
		{
			name:                 "valid credentials (container) with metadata",
			namespace:            "default",
			serviceInfo:          &v1alpha1.ServiceInfo{Name: "service-a", Secret: "metadata-with-credential-key", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
		},
		{
			name:        "malformed metadata",
			namespace:   "default",
			serviceInfo: &v1alpha1.ServiceInfo{Name: "service-a", Secret: "malformed-metadata", Class: "xzy"},
			expectError: true,
			errorMsg:    "could not parse metadata from secret malformed-metadata: invalid character '/' looking for beginning of value",
		},
		{
			name:                 "valid credentials (multiple properties) with metadata",
			namespace:            "default",
			serviceInfo:          &v1alpha1.ServiceInfo{Name: "service-a", Secret: "metadata-with-credential-properties", Class: "xzy"},
			expectedInstanceName: "service-a",
			expectedLabel:        "xyz",
			expectTags:           true,
		},
	}
	c, _ := createTestClient()
	for i := range cases {
		t.Run(cases[i].name, func(t *testing.T) {
			config := &cases[i]
			entry, err := CreateVCAPEntryFromSecret(config.serviceInfo, config.namespace, c)
			if err != nil {
				if !config.expectError {
					t.Errorf("unexpected error in test case: %s", config.name)
				}
				if config.errorMsg != "" && err.Error() != config.errorMsg {
					t.Errorf("error differs from expected for test case: %s", config.name)
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
	c, _ := createTestClient()

	// test successful read
	secretName := "metadata-with-credential-key"
	credentials, err := ReadServiceCredentialsFromSecret[map[string]string](&v1alpha1.ServiceInfo{Name: "service-a", Class: "xyz", Secret: secretName}, "default", c)
	if err != nil {
		t.Errorf("could not read credentials from secret %s", secretName)
	}
	if (*credentials)["user"] != "a-user" || (*credentials)["password"] != "some-pass" {
		t.Errorf("credential attributes from secret %s not as expected", secretName)
	}

	// test with type mismatch
	_, err = ReadServiceCredentialsFromSecret[[]string](&v1alpha1.ServiceInfo{Name: "service-a", Class: "xyz", Secret: secretName}, "default", c)
	if err == nil {
		t.Errorf("expected error when reading credentials as array from secret %s", secretName)
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
