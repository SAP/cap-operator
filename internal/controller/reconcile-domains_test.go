/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"os"
	"testing"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const envDNS = "env-ingress.some.cluster.sap"

func TestController_reconcileOperatorDomains(t *testing.T) {
	tests := []struct {
		name                  string
		createCA              bool
		createCA2             bool
		updateCA              bool
		createIngress         bool
		withoutDNSNames       bool
		useEnvDNS             bool
		cleanUpDomains        bool
		wantErr               bool
		expectDomainResources bool
		enableCertManagerEnv  bool
	}{
		{
			name:                  "Test without CAPApplication",
			wantErr:               false,
			expectDomainResources: false,
		},
		{
			name:                  "Test with CAPApplication but without Ingress GW",
			createCA:              true,
			wantErr:               true,
			expectDomainResources: false,
		},
		{
			name:                  "Test with CAPApplication and Ingress GW",
			createCA:              true,
			createIngress:         true,
			wantErr:               false,
			expectDomainResources: true,
		},
		{
			name:                  "Test cleanup after creation",
			createCA:              true,
			createIngress:         true,
			wantErr:               false,
			cleanUpDomains:        true,
			expectDomainResources: false,
		},
		{
			name:                  "Test with multiple CAPApplications and Ingress GW",
			createCA:              true,
			createCA2:             true,
			createIngress:         true,
			wantErr:               false,
			expectDomainResources: true,
		},
		{
			name:                  "Test with multiple CAPApplications and Ingress GW without DNS names",
			createCA:              true,
			createCA2:             true,
			createIngress:         true,
			withoutDNSNames:       true,
			wantErr:               true, // ingress gateway service not annotated with dns target name for CAPApplication default.ca-test-name
			expectDomainResources: false,
		},
		{
			name:                  "Test with multiple CAPApplications and Ingress GW without DNS names but DNS_TARGET env",
			createCA:              true,
			createCA2:             true,
			createIngress:         true,
			withoutDNSNames:       true,
			useEnvDNS:             true,
			wantErr:               false,
			expectDomainResources: true, // Creates resources because of DNS_TARGET env
		},
		// {
		// 	name:                  "Test cleanup with multiple CAPApplications and Ingress GW",
		// 	createCA:              true,
		// 	createCA2:             true,
		// 	createIngress:         true,
		// 	cleanUpDomains:        true,
		// 	wantErr:               false,
		// 	expectDomainResources: true,
		// },
		{
			name:                  "Test update with CAPApplication and Ingress GW",
			createCA:              true,
			updateCA:              true,
			createIngress:         true,
			wantErr:               false,
			expectDomainResources: true,
		},
		{
			name:                  "Test with CAPApplication and Ingress GW (enableCertManagerEnv)",
			createCA:              true,
			createIngress:         true,
			enableCertManagerEnv:  true,
			wantErr:               false,
			expectDomainResources: true,
		},
		{
			name:                  "Test cleanup after creation (enableCertManagerEnv)",
			createCA:              true,
			createIngress:         true,
			enableCertManagerEnv:  true,
			wantErr:               false,
			cleanUpDomains:        true,
			expectDomainResources: false,
		},
		{
			name:                  "Test with multiple CAPApplications and Ingress GW (enableCertManagerEnv)",
			createCA:              true,
			createCA2:             true,
			createIngress:         true,
			enableCertManagerEnv:  true,
			wantErr:               false,
			expectDomainResources: true,
		},
		// {
		// 	name:                  "Test cleanup with multiple CAPApplications and Ingress GW (enableCertManagerEnv)",
		// 	createCA:              true,
		// 	createCA2:             true,
		// 	createIngress:         true,
		// 	cleanUpDomains:        true,
		// 	enableCertManagerEnv:     true,
		// 	wantErr:               false,
		// 	expectDomainResources: true,
		// },
		{
			name:                  "Test update with CAPApplication and Ingress GW (enableCertManagerEnv)",
			createCA:              true,
			updateCA:              true,
			createIngress:         true,
			enableCertManagerEnv:  true,
			wantErr:               false,
			expectDomainResources: true,
		},
	}
	defer os.Unsetenv(certManagerEnv)
	defer os.Unsetenv(dnsTargetEnv)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.enableCertManagerEnv {
				os.Setenv(certManagerEnv, certManagerCertManagerIO)
			} else {
				os.Setenv(certManagerEnv, certManagerGardener)
			}
			if tt.useEnvDNS {
				os.Setenv(dnsTargetEnv, envDNS)
			}
			var c *Controller
			var ca *v1alpha1.CAPApplication
			var ca2 *v1alpha1.CAPApplication
			var ingressRes *ingressResources
			if tt.createCA {
				ca = createCaCRO(caCroName, false)
				if tt.createCA2 {
					ca2 = ca.DeepCopy()
					ca2.Name += "2"
					// Test with duplicate domain
					ca2.Spec.Domains.Secondary = []string{secondaryDomain, "2" + secondaryDomain}
				}
			}

			if tt.createIngress {
				dns := dnsTarget
				if tt.withoutDNSNames {
					dns = ""
				}
				ingressRes = createIngressResource(ingressGWName, ca, dns)
			}

			// Deregister metrics
			defer deregisterMetrics()

			c = getTestController(testResources{
				cas:       []*v1alpha1.CAPApplication{ca, ca2},
				ingressGW: []*ingressResources{ingressRes},
			})

			q := QueueItem{
				// Key: ResourceOperatorDomains,
				ResourceKey: NamespacedResourceKey{
					Namespace: metav1.NamespaceAll,
					Name:      "",
				},
			}
			err := c.reconcileOperatorDomains(context.TODO(), q, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Controller.reconcileOperatorDomains() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.updateCA {
				var gw *istionwv1.Gateway
				listGWs, _ := c.istioClient.NetworkingV1().Gateways(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
				if len(listGWs.Items) > 0 {
					gw = listGWs.Items[0]
					generateMetaObjName(gw)
				}
				var gardenerCert *certv1alpha1.Certificate
				var certManagerCert *certManagerv1.Certificate
				if tt.enableCertManagerEnv {
					certManagerCertList, _ := c.certManagerCertificateClient.CertmanagerV1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
					if len(certManagerCertList.Items) > 0 {
						certManagerCert = &certManagerCertList.Items[0]
						certManagerCert.Name = gw.Name
					}
				} else {
					gardenerCertList, _ := c.gardenerCertificateClient.CertV1alpha1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
					if len(gardenerCertList.Items) > 0 {
						gardenerCert = &gardenerCertList.Items[0]
						gardenerCert.Name = gw.Name
					}
				}
				ca.Spec.Domains.Secondary = []string{"2" + secondaryDomain, "3" + secondaryDomain}

				// Deregister metrics before starting new controller again
				deregisterMetrics()

				c = getTestController(testResources{
					cas:             []*v1alpha1.CAPApplication{ca, ca2},
					gateway:         gw,
					gardenerCert:    gardenerCert,
					certManagerCert: certManagerCert,
					ingressGW:       []*ingressResources{ingressRes},
				})
				err = c.reconcileOperatorDomains(context.TODO(), q, 0)
				if (err != nil) != tt.wantErr {
					t.Errorf("Controller.reconcileOperatorDomains() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			if tt.cleanUpDomains {
				var gw *istionwv1.Gateway
				var ingressGW2 *ingressResources
				listGWs, _ := c.istioClient.NetworkingV1().Gateways(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
				if len(listGWs.Items) > 0 {
					gw = listGWs.Items[0]
					generateMetaObjName(gw)
				}
				var gardenerCert *certv1alpha1.Certificate
				var certManagerCert *certManagerv1.Certificate
				if tt.enableCertManagerEnv {
					certManagerCertList, _ := c.certManagerCertificateClient.CertmanagerV1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
					if len(certManagerCertList.Items) > 0 {
						certManagerCert = &certManagerCertList.Items[0]
						certManagerCert.Name = gw.Name
					}
				} else {
					gardenerCertList, _ := c.gardenerCertificateClient.CertV1alpha1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
					if len(gardenerCertList.Items) > 0 {
						gardenerCert = &gardenerCertList.Items[0]
						gardenerCert.Name = gw.Name
					}
				}
				ca.Spec.Domains.Secondary = []string{}
				if tt.createCA2 {
					ca2.Spec.Domains.IstioIngressGatewayLabels[0].Value += "2"
					ca2.Spec.Domains.IstioIngressGatewayLabels[1].Value += "2"
					ingressGW2 = createIngressResource(ingressGWName+"2", ca2, "Something.that.surely.exceeds.the.64char.limit."+dnsTarget)
				}

				// Deregister metrics before starting new controller again
				deregisterMetrics()

				c = getTestController(testResources{
					cas:             []*v1alpha1.CAPApplication{ca, ca2},
					gateway:         gw,
					gardenerCert:    gardenerCert,
					certManagerCert: certManagerCert,
					ingressGW:       []*ingressResources{ingressRes, ingressGW2},
				})

				err = c.reconcileOperatorDomains(context.TODO(), q, 0)
				if (err != nil) != tt.wantErr {
					t.Errorf("Controller.reconcileOperatorDomains() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			var gw *istionwv1.Gateway
			listGWs, _ := c.istioClient.NetworkingV1().Gateways(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
			if len(listGWs.Items) > 0 {
				gw = listGWs.Items[0]
			}
			var cert interface{}
			if tt.enableCertManagerEnv {
				certManagerCertList, _ := c.certManagerCertificateClient.CertmanagerV1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
				if len(certManagerCertList.Items) > 0 {
					cert = &certManagerCertList.Items[0]
				}
			} else {
				gardenerCertList, _ := c.gardenerCertificateClient.CertV1alpha1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: labels.SelectorFromValidatedSet(map[string]string{LabelOwnerIdentifierHash: sha1Sum(CAPOperator, OperatorDomains)}).String()})
				if len(gardenerCertList.Items) > 0 {
					cert = &gardenerCertList.Items[0]
				}
			}

			if tt.expectDomainResources {
				if gw == nil {
					t.Errorf("Controller.reconcileOperatorDomains() error = Expected OperatorDomain Gateway missing")
				}
				if cert == nil {
					t.Errorf("Controller.reconcileOperatorDomains() error = Expected OperatorDomain Certificate missing")
				}
			} else {
				if gw != nil {
					t.Errorf("Controller.reconcileOperatorDomains() error = Unexpected OperatorDomain Gateway: %v", gw)
				}
				if cert != nil {
					t.Errorf("Controller.reconcileOperatorDomains() error = Unexpected OperatorDomain Certificate: %v", cert)
				}
			}
		})
	}
}
