/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"net/http"
	"os"
	"strconv"

	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	handler "github.com/sap/cap-operator/cmd/server/internal"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
)

func main() {
	subHandler := getSubscriptionHandler()
	http.HandleFunc("/provision/", subHandler.HandleRequest)

	// Default port
	port := "4000"

	// Get Port from env
	portEnv := os.Getenv("PORT")
	if portEnv != "" {
		port = portEnv
	}

	// Default TLS enabled = false
	tlsEnabled := false

	// Get TLS details from env
	var tlsCertFile, tlsKeyFile string
	tlsEnv := os.Getenv("TLS_ENABLED")
	if tlsEnv != "" {
		tlsEnvBool, err := strconv.ParseBool(tlsEnv)
		if err != nil {
			klog.Error("Error parsing TLS_ENABLED: ", err.Error())
		}
		tlsEnabled = tlsEnvBool
		tlsCertFile = os.Getenv("TLS_CERT")
		tlsKeyFile = os.Getenv("TLS_KEY")
	}

	klog.Info("Server running and listening (provider) with TLS: ", tlsEnabled, ", at port: ", port)
	if tlsEnabled {
		klog.Fatal(http.ListenAndServeTLS(":"+port, tlsCertFile, tlsKeyFile, nil))
	} else {
		http.ListenAndServe(":"+port, nil)
	}
}

func getSubscriptionHandler() *handler.SubscriptionHandler {
	config := util.GetConfig()

	customResourceClientSet, err := versioned.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for custom resources: ", err.Error())
	}

	kubernetesClientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for k8s resources: ", err.Error())
	}

	return handler.NewSubscriptionHandler(customResourceClientSet, kubernetesClientset)
}
