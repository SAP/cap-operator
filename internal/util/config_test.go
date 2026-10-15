/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetNamespace(t *testing.T) {
	t.Run("from POD_NAMESPACE env", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "my-namespace")
		if ns := GetNamespace(); ns != "my-namespace" {
			t.Errorf("expected namespace from env, got: %s", ns)
		}
	})

	t.Run("fallback to default", func(t *testing.T) {
		// no POD_NAMESPACE and no service account token file available in the test environment
		t.Setenv("POD_NAMESPACE", "")
		if ns := GetNamespace(); ns != "default" {
			t.Errorf("expected fallback namespace 'default', got: %s", ns)
		}
	})
}

func TestGetConfig_FromFile(t *testing.T) {
	// write a minimal, valid kubeconfig and point KUBECONFIG at it so the
	// out-of-cluster fallback resolves it (in-cluster config is unavailable in tests)
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatalf("could not write test kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", path)

	config := GetConfig()
	if config == nil {
		t.Fatal("expected a non-nil config from the kubeconfig file")
	}
	if config.Host != "https://127.0.0.1:6443" {
		t.Errorf("expected host from the kubeconfig file, got: %s", config.Host)
	}
}
