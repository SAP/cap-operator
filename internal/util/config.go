/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"io/ioutil"
	"os"
	"path"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

func GetConfig() *rest.Config {
	// Try to load config from within cluster
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Warning("Could not load config from cluster; will attempt to load from file")

		// Load config from local/home directory
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		pwd, err := os.Getwd()
		if err != nil {
			klog.Fatal("Could not determine working directory")
		}
		loadingRules.Precedence = append(loadingRules.Precedence, path.Join(pwd, ".kubeconfig"))
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
		config, err = clientConfig.ClientConfig()
		if err != nil {
			klog.Fatal("Error: ", err)
			return nil
		} else {
			klog.Info("Found config file in: ", clientConfig.ConfigAccess().GetDefaultFilename())
		}
	} else {
		klog.Info("Found config in cluster")
	}

	return config
}

func GetNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}
