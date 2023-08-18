/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"

	certManager "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	gardenerCert "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	dns "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned"
	"github.com/google/uuid"
	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	istio "istio.io/client-go/pkg/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LeaseLockName = "capoperator-lease-lock"
)

func main() {
	config := util.GetConfig()
	if config == nil {
		klog.Fatal("Config not found")
	}

	leaseLockNamespace := util.GetNamespace()
	leaseLockId := uuid.New().String()

	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatal("Could not create kubernetes core client: ", err.Error())
	}

	crdClient, err := versioned.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for custom resources: ", err.Error())
	}

	istioClient, err := istio.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for istio resources: ", err.Error())
	}

	certClient, err := gardenerCert.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for certificate resources: ", err.Error())
	}

	certManagerClient, err := certManager.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for certManager certificate resources: ", err.Error())
	}

	dnsClient, err := dns.NewForConfig(config)
	if err != nil {
		klog.Fatal("could not create client for dns resources: ", err.Error())
	}

	// context for the reconciliation controller
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle sys exits to ensure cleanup of controller code before stopping leading
	leaseCh := make(chan os.Signal, 1)
	signal.Notify(leaseCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-leaseCh
		klog.Info("Interrupt received, shutting down operator context")
		cancel()
	}()

	// Create a LeaseLock resource
	leaseLock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      LeaseLockName,
			Namespace: leaseLockNamespace,
		},
		Client: coreClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: leaseLockId,
		},
	}

	// Run leader election
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            leaseLock,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     5 * time.Second,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				klog.Infof("Started leading: %s - %s", LeaseLockName, leaseLockId)

				checkDone := make(chan bool, 1)
				go checkHashedLabels(checkDone, coreClient, crdClient, istioClient, certClient, certManagerClient, dnsClient)
				<-checkDone
				klog.Info("check & update of hashed labels done")

				c := controller.NewController(coreClient, crdClient, istioClient, certClient, certManagerClient, dnsClient)
				go c.Start(ctx)
			},
			OnStoppedLeading: func() {
				klog.Infof("Stopped leading: %s - %s", LeaseLockName, leaseLockId)
				os.Exit(0)
			},
			OnNewLeader: func(id string) {
				if id == leaseLockId {
					return
				}
				klog.Infof("Leader exists: %s", id)
			},
		},
	})
}
