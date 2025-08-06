/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
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

const (
	subsctiptionHandlerMetricPrefix = "cap_op_subscription_requests"
	subscriptionHandlerDesc         = "subscription-server requests."
)

func main() {
	klog.SetLogger(util.GetLogger())
	subHandler := getSubscriptionHandler()

	http.HandleFunc("/provision/", util.InstrumentHttpHandler(subHandler.HandleSaaSRequest, subsctiptionHandlerMetricPrefix, subscriptionHandlerDesc))
	http.HandleFunc("/saas/provision/", util.InstrumentHttpHandler(subHandler.HandleSaaSRequest, subsctiptionHandlerMetricPrefix+"_saas", subscriptionHandlerDesc))
	http.HandleFunc("/sms/provision/", util.InstrumentHttpHandler(subHandler.HandleSMSRequest, subsctiptionHandlerMetricPrefix+"_sms", subscriptionHandlerDesc))

	// Initialize/start metrics server
	util.InitMetricsServer()

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
			klog.ErrorS(err, "Error parsing TLS_ENABLED")
		}
		tlsEnabled = tlsEnvBool
		tlsCertFile = os.Getenv("TLS_CERT")
		tlsKeyFile = os.Getenv("TLS_KEY")
	}

	klog.InfoS("Server running and listening", "tls enabled", tlsEnabled, "port", port)
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
