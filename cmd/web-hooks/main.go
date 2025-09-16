/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"net/http"
	"os"
	"strconv"

	handler "github.com/sap/cap-operator/cmd/web-hooks/internal/handler"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	"k8s.io/klog/v2"
)

type ServerParameters struct {
	port       int    // webhook server port
	certFile   string // path to TLS certificate for https
	keyFile    string // path to TLS key matching for certificate
	tlsEnabled bool   // indicates if TLS is enabled
}

var parameters ServerParameters

func main() {
	klog.SetLogger(util.GetLogger())
	// check env for relevant values
	portEnv := os.Getenv("WEBHOOK_PORT")
	port := 8443
	var err error

	if portEnv != "" {
		port, err = strconv.Atoi(portEnv)
		if err != nil {
			klog.ErrorS(err, "Error parsing Webhook server port")
		}
	}

	parameters.port = port

	t := os.Getenv("TLS_ENABLED")
	tlsEnabled := false

	if t != "" {
		tlsEnabled, err = strconv.ParseBool(t)
		if err != nil {
			klog.ErrorS(err, "Error parsing tls")
		}
	}
	parameters.tlsEnabled = tlsEnabled

	parameters.certFile = os.Getenv("TLS_CERT")
	parameters.keyFile = os.Getenv("TLS_KEY")

	if err != nil {
		klog.Fatal("Config build: ", err.Error())
	}

	config := util.GetConfig()
	crdClient, err := versioned.NewForConfig(config)
	if err != nil {
		klog.Fatalf("could not create client for custom resources: %v", err.Error())
	}

	whHandler := &handler.WebhookHandler{
		CrdClient: crdClient,
	}

	http.HandleFunc("/validate", whHandler.Validate)
	http.HandleFunc("/mutate", whHandler.Mutate)

	if parameters.tlsEnabled {
		klog.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(parameters.port), parameters.certFile, parameters.keyFile, nil))
	} else {
		klog.Fatal(http.ListenAndServe(":"+strconv.Itoa(parameters.port), nil))
	}
}
