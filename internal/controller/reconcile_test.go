/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certManagerFake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certfake "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned/fake"
	dnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	dnsfake "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned/fake"
	promopFake "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/fake"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
)

const (
	caCroName          = "ca-test-name"
	providerSubDomain  = "provider-subdomain"
	consumerSubDomain  = "consumer-subdomain"
	providerTenantId   = "provider-tenant-id"
	consumerTenantId   = "consumer-tenant-id"
	cavCroName         = "cav-test-name"
	btpApplicationName = "some-app-name"
	globalAccountId    = "global-id-test"
	primaryDomain      = "app.sme.sap.com"
	secondaryDomain    = "sec.sme.sap.com"
	defaultVersion     = "0.0.1"
)

type ingressResources struct {
	service *corev1.Service
	pod     *corev1.Pod
}

type testResources struct {
	cas             []*v1alpha1.CAPApplication
	cavs            []*v1alpha1.CAPApplicationVersion
	cats            []*v1alpha1.CAPTenant
	ctops           []*v1alpha1.CAPTenantOperation
	ingressGW       []*ingressResources
	gateway         *istionwv1.Gateway
	gardenerCert    *certv1alpha1.Certificate
	certManagerCert *certManagerv1.Certificate
	dnsEntry        *dnsv1alpha1.DNSEntry
	preventStart    bool
}

func createCaCRO(name string, withFinalizer bool) *v1alpha1.CAPApplication {
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1alpha1.CAPApplicationSpec{
			Domains: v1alpha1.ApplicationDomains{
				Primary:   primaryDomain,
				Secondary: []string{secondaryDomain},
				IstioIngressGatewayLabels: []v1alpha1.NameValue{
					{
						Name:  "istio",
						Value: "ingressgateway",
					},
					{
						Name:  "app",
						Value: "istio-ingressgateway",
					},
				},
			},
			GlobalAccountId: globalAccountId,
			BTPAppName:      btpApplicationName,
			Provider: v1alpha1.BTPTenantIdentification{
				SubDomain: providerSubDomain,
				TenantId:  providerTenantId,
			},
			BTP: v1alpha1.BTP{
				Services: []v1alpha1.ServiceInfo{
					{
						Class:  "xsuaa",
						Name:   "test-xsuaa",
						Secret: "test-xsuaa-sec",
					},
					{
						Class:  "saas-registry",
						Name:   "test-saas",
						Secret: "test-saas-sec",
					},
					{
						Class:  "service-manager",
						Name:   "test-sm",
						Secret: "test-sm-sec",
					},
					{
						Class:  "destination",
						Name:   "test-dest",
						Secret: "test-dest-sec",
					},
					{
						Class:  "html5-apps-repo",
						Name:   "test-html-host",
						Secret: "test-html-host-sec",
					},
					{
						Class:  "html5-apps-repo",
						Name:   "test-html-rt",
						Secret: "test-html-rt-sec",
					},
				},
			},
		},
	}

	if withFinalizer {
		ca.Finalizers = []string{FinalizerCAPApplication}
	}

	return ca
}

func createCavCRO(name string, state v1alpha1.CAPApplicationVersionState, version string) *v1alpha1.CAPApplicationVersion {
	status := metav1.ConditionFalse
	if state == v1alpha1.CAPApplicationVersionStateReady || state == v1alpha1.CAPApplicationVersionStateDeleting {
		status = metav1.ConditionTrue
	}
	return &v1alpha1.CAPApplicationVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				LabelOwnerIdentifierHash: sha1Sum(metav1.NamespaceDefault, caCroName),
			},
		},
		Spec: v1alpha1.CAPApplicationVersionSpec{
			CAPApplicationInstance: caCroName,
			Version:                version,
			Workloads: []v1alpha1.WorkloadDetails{
				{
					Name: "cap-backend-server",
					ConsumedBTPServices: []string{
						"test-xsuaa",
						"test-saas",
					},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentCAP,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "test://image",
						},
					},
				},
				{
					Name:                "app-router",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						CommonDetails: v1alpha1.CommonDetails{
							Image: "test://image",
						},
					},
				},
			},
		},
		Status: v1alpha1.CAPApplicationVersionStatus{
			GenericStatus: v1alpha1.GenericStatus{
				Conditions: []metav1.Condition{
					{
						Status: status,
						Type:   string(v1alpha1.ConditionTypeReady),
					},
				},
			},
			State: state,
		},
	}
}

// Replace GenerateName logic from k8s as fake clients do not generate a name
func generateName(namePrefix string) string {
	return namePrefix + rand.String(5)
}

func generateMetaObjName(obj interface{}) {
	metaObj, _ := meta.Accessor(obj)
	if metaObj.GetName() == "" && metaObj.GetGenerateName() != "" {
		metaObj.SetName(generateName(metaObj.GetGenerateName()))
	}
}

func createCatCRO(caName string, tenantType string, withFinalizers bool) *v1alpha1.CAPTenant {
	cat := &v1alpha1.CAPTenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{caName, tenantType}, "-"),
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1alpha1.CAPTenantSpec{
			CAPApplicationInstance:  caCroName,
			BTPTenantIdentification: v1alpha1.BTPTenantIdentification{},
			Version:                 defaultVersion,
		},
		Status: v1alpha1.CAPTenantStatus{
			CurrentCAPApplicationVersionInstance: cavCroName,
			GenericStatus:                        v1alpha1.GenericStatus{},
		},
	}

	if tenantType == TenantTypeProvider {
		cat.Spec.BTPTenantIdentification.TenantId = providerTenantId
		cat.Spec.BTPTenantIdentification.SubDomain = providerSubDomain
	} else {
		cat.Spec.BTPTenantIdentification.TenantId = consumerTenantId
		cat.Spec.BTPTenantIdentification.SubDomain = consumerSubDomain
	}

	if withFinalizers {
		cat.Finalizers = []string{FinalizerCAPTenant}
	}
	return cat
}

func addRuntimeObjects(objects *[]runtime.Object, object runtime.Object) {
	if reflect.ValueOf(object).Elem().IsValid() {
		*objects = append(*objects, object)
	}
}

func getTestController(resources testResources) *Controller {
	crdObjects := []runtime.Object{}
	coreObjects := []runtime.Object{}
	istioObjects := []runtime.Object{}
	gardenerCertObjects := []runtime.Object{}
	certManagerCertObjects := []runtime.Object{}
	dnsObjects := []runtime.Object{}

	for _, ca := range resources.cas {
		addRuntimeObjects(&crdObjects, ca)
	}

	for _, cav := range resources.cavs {
		addRuntimeObjects(&crdObjects, cav)
	}

	for _, cat := range resources.cats {
		addRuntimeObjects(&crdObjects, cat)
	}

	for _, ctop := range resources.ctops {
		addRuntimeObjects(&crdObjects, ctop)
	}

	for _, ingressGW := range resources.ingressGW {
		if ingressGW != nil {
			addRuntimeObjects(&coreObjects, ingressGW.service)
			addRuntimeObjects(&coreObjects, ingressGW.pod)
		}
	}

	addRuntimeObjects(&istioObjects, resources.gateway)
	addRuntimeObjects(&gardenerCertObjects, resources.gardenerCert)
	addRuntimeObjects(&certManagerCertObjects, resources.certManagerCert)
	addRuntimeObjects(&dnsObjects, resources.dnsEntry)

	coreClient := k8sfake.NewSimpleClientset(coreObjects...)
	coreClient.PrependReactor("create", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		act := action.(k8stesting.CreateAction)
		obj := act.GetObject()
		generateMetaObjName(obj)
		return false, obj, nil
	})

	crdClient := fake.NewSimpleClientset(crdObjects...)

	promopClient := promopFake.NewSimpleClientset()

	istioClient := istiofake.NewSimpleClientset(istioObjects...)

	certClient := certfake.NewSimpleClientset(gardenerCertObjects...)

	certManagerCertClient := certManagerFake.NewSimpleClientset(certManagerCertObjects...)

	dnsClient := dnsfake.NewSimpleClientset(dnsObjects...)

	c := NewController(coreClient, crdClient, istioClient, certClient, certManagerCertClient, dnsClient, promopClient)

	for _, ca := range resources.cas {
		if ca != nil {
			c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Informer().GetIndexer().Add(ca)
		}
	}

	for _, cav := range resources.cavs {
		if cav != nil {
			c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Informer().GetIndexer().Add(cav)
		}
	}

	for _, cat := range resources.cats {
		if cat != nil {
			c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Informer().GetIndexer().Add(cat)
		}
	}

	for _, ctop := range resources.ctops {
		if ctop != nil {
			c.crdInformerFactory.Sme().V1alpha1().CAPTenantOperations().Informer().GetIndexer().Add(ctop)
		}
	}

	if resources.gateway != nil {
		c.istioClient.NetworkingV1().Gateways(resources.gateway.Namespace).Create(context.TODO(), resources.gateway, metav1.CreateOptions{})
		c.istioInformerFactory.Networking().V1().Gateways().Informer().GetIndexer().Add(resources.gateway)
	}

	if resources.gardenerCert != nil {
		c.gardenerCertInformerFactory.Cert().V1alpha1().Certificates().Informer().GetIndexer().Add(resources.gardenerCert)
	}

	if resources.certManagerCert != nil {
		c.certManagerInformerFactory.Certmanager().V1().Certificates().Informer().GetIndexer().Add(resources.certManagerCert)
	}

	if resources.dnsEntry != nil {
		c.gardenerDNSInformerFactory.Dns().V1alpha1().DNSEntries().Informer().GetIndexer().Add(resources.dnsEntry)
	}

	for _, ingressGW := range resources.ingressGW {
		if ingressGW != nil {
			c.kubeInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(ingressGW.service)
			c.kubeInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(ingressGW.pod)
		}
	}
	if !resources.preventStart {
		stopCh := make(chan struct{})
		defer close(stopCh)

		c.crdInformerFactory.Start(stopCh)
		c.kubeInformerFactory.Start(stopCh)
		c.istioInformerFactory.Start(stopCh)
		switch certificateManager() {
		case certManagerGardener:
			c.gardenerCertInformerFactory.Start(stopCh)
		case certManagerCertManagerIO:
			c.certManagerInformerFactory.Start(stopCh)
		}
		c.gardenerDNSInformerFactory.Start(stopCh)
	}

	return c
}

func TestMain(m *testing.M) {
	os.Setenv(certManagerEnv, "gardener")
	os.Setenv(dnsManagerEnv, "gardener")
	defer os.Setenv(certManagerEnv, "")
	defer os.Setenv(dnsManagerEnv, "")
	m.Run()
}

func TestGetLatestReadyCAPApplicationVersion(t *testing.T) {
	tests := []struct {
		testName        string
		status          v1alpha1.CAPApplicationVersionState
		number          int
		expectedVersion string
	}{
		{
			testName:        "when getLatestReadyCAPApplicationVersion() is called with no CAVs",
			status:          "",
			number:          0,
			expectedVersion: "",
		},
		{
			testName:        "when getLatestReadyCAPApplicationVersion() is called with one CAV in ready state",
			status:          v1alpha1.CAPApplicationVersionStateReady,
			number:          1,
			expectedVersion: "0.0.1",
		},
		{
			testName:        "when getLatestReadyCAPApplicationVersion() is called with one CAV in processing (not ready) state",
			status:          v1alpha1.CAPApplicationVersionStateProcessing,
			number:          9,
			expectedVersion: "",
		},
		{
			testName:        "when getLatestReadyCAPApplicationVersion() is called with multiple CAVs in ready states",
			status:          v1alpha1.CAPApplicationVersionStateReady,
			number:          18,
			expectedVersion: "0.9.0",
		},
		{
			testName:        "when getLatestReadyCAPApplicationVersion() is called with multiple CAVs in mixed states",
			status:          "mixed",
			number:          18,
			expectedVersion: "0.0.9",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ca := createCaCRO(caCroName, true)
			var cavs []*v1alpha1.CAPApplicationVersion

			for i := 1; i <= test.number; i++ {
				var state v1alpha1.CAPApplicationVersionState
				// for mixed states - mark the latest versions in processing (not-ready) state
				if test.status == "mixed" {
					if i > 9 {
						state = v1alpha1.CAPApplicationVersionStateProcessing
					} else {
						state = v1alpha1.CAPApplicationVersionStateReady
					}
				} else {
					state = test.status
				}

				indexString := strconv.Itoa(i)
				var version string
				if i > 9 && i < 20 {
					version = "0." + strconv.Itoa((i+1)-10) + ".0" // 0.1.0 - 0.9.0
				} else {
					version = "0.0." + indexString // 0.0.1 - 0.0.9
				}
				cav := createCavCRO(cavCroName+version, state, version)

				cavs = append(cavs, cav)
			}

			// Deregister metrics at the end of the test
			defer deregisterMetrics()

			c := getTestController(testResources{
				cas:  []*v1alpha1.CAPApplication{ca},
				cavs: cavs,
			})

			latestCav, err := c.getLatestReadyCAPApplicationVersion(ca, false)

			if test.status == v1alpha1.CAPApplicationVersionStateReady || test.status == "mixed" {
				if err != nil {
					t.Fatal("Error should not be thrown")
				}

				if latestCav.Spec.Version != test.expectedVersion {
					t.Fatal("Expected version not returned")
				}
			} else if err == nil {
				t.Fatal("Error should be thrown")
			}
		})
	}
}

func TestGetLatestCAPApplicationVersion(t *testing.T) {
	tests := []struct {
		testName        string
		expectError     bool
		status          string
		number          int
		expectedVersion string
	}{
		{
			testName:        "when getLatestCAPApplicationVersion() is called with no CAVs",
			expectError:     true,
			number:          0,
			expectedVersion: "",
		},
		{
			testName:        "when getLatestCAPApplicationVersion() is called with one CAV in ready state",
			expectError:     false,
			number:          1,
			expectedVersion: "0.0.1",
		},
		{
			testName:        "when getLatestCAPApplicationVersion() is called with one CAV in processing (not ready) state",
			expectError:     false,
			status:          "mixed",
			number:          10,
			expectedVersion: "0.1.0",
		},
		{
			testName:        "when getLatestCAPApplicationVersion() is called with multiple CAVs in ready states",
			expectError:     false,
			number:          18,
			expectedVersion: "0.9.0",
		},
		{
			testName:        "when getLatestCAPApplicationVersion() is called with multiple CAVs in mixed states",
			status:          "mixed",
			number:          18,
			expectedVersion: "0.9.0",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ca := createCaCRO(caCroName, true)
			var cavs []*v1alpha1.CAPApplicationVersion

			for i := 1; i <= test.number; i++ {
				var state v1alpha1.CAPApplicationVersionState
				// for mixed states - mark the latest versions in processing (not-ready) state
				if test.status == "mixed" {
					if i > 9 {
						state = v1alpha1.CAPApplicationVersionStateProcessing
					} else {
						state = v1alpha1.CAPApplicationVersionStateReady
					}
				} else {
					state = v1alpha1.CAPApplicationVersionStateReady
				}

				indexString := strconv.Itoa(i)
				var version string
				if i > 9 && i < 20 {
					version = "0." + strconv.Itoa((i+1)-10) + ".0" // 0.1.0 - 0.9.0
				} else {
					version = "0.0." + indexString // 0.0.1 - 0.0.9
				}
				cav := createCavCRO(cavCroName+version, state, version)

				cavs = append(cavs, cav)
			}

			// Deregister metrics at the end of the test
			defer deregisterMetrics()

			c := getTestController(testResources{
				cas:  []*v1alpha1.CAPApplication{ca},
				cavs: cavs,
			})

			latestCav, err := c.getLatestCAPApplicationVersion(ca)

			if test.expectError == false {
				if err != nil {
					t.Fatal("Error should not be thrown")
				}

				if latestCav.Spec.Version != test.expectedVersion {
					t.Fatal("Expected version not returned")
				}
			} else if err == nil {
				t.Fatal("Error should be thrown")
			}
		})
	}
}
