/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	fakeCrdClient "github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	cavName    = "someCavName"
	catName    = "someCatName"
	caName     = "someCaName"
	uid        = "someUID"
	apiVersion = "apiVersion"
	subDomain  = "someSubdomain"
	tenantId   = "someTenantId"
)

type updateType int

const (
	noUpdate updateType = iota
	providerUpdate
	appInstanceUpdate
	registrySecretsUpdate
	consumedBTPServicesUpdate
	versionUpdate
	imageUpdate
	emptyUpdate
	domainsUpdate
	useDomains
)

func createCaCRO() *v1alpha1.CAPApplication {
	return &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      caName,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1alpha1.CAPApplicationSpec{
			DomainRefs: []v1alpha1.DomainRefs{
				{
					Kind: "Domain",
					Name: "primaryDomain",
				},
				{
					Kind: "ClusterDomain",
					Name: "secondaryDomain",
				},
			},
			GlobalAccountId: "globalAccountId",
			BTPAppName:      "btpApplicationName",
			Provider: v1alpha1.BTPTenantIdentification{
				SubDomain: subDomain,
				TenantId:  tenantId,
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
		Status: v1alpha1.CAPApplicationStatus{
			State: v1alpha1.CAPApplicationStateConsistent,
		},
	}
}

func getHttpRequest(operation admissionv1.Operation, crdType string, crdName string, change updateType, t *testing.T) (*http.Request, *httptest.ResponseRecorder) {
	admissionReview, err := createAdmissionRequest(operation, crdType, crdName, change)
	if err != nil {
		t.Fatal("admission review error")
	}
	bytesRequest, err := json.Marshal(admissionReview)
	if err != nil {
		t.Fatal("marshal error")
	}
	req := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))
	w := httptest.NewRecorder()
	return req, w
}

func createAdmissionRequest(operation admissionv1.Operation, crdType string, crdName string, change updateType) (*admissionv1.AdmissionReview, error) {
	admissionReview := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       crdType,
			APIVersion: apiVersion,
		},
		Request: &admissionv1.AdmissionRequest{
			Name: crdName,
			Kind: metav1.GroupVersionKind{
				Kind: crdType,
			},
			Operation: operation,
			UID:       uid,
		},
	}

	var rawBytes []byte
	var rawBytesOld []byte
	var err error

	switch crdType {

	case v1alpha1.CAPApplicationKind:
		crd := &ResponseCa{}
		if change != emptyUpdate {
			crd = &ResponseCa{
				Metadata: Metadata{
					Name:      caName,
					Namespace: metav1.NamespaceDefault,
				},
				Spec: &v1alpha1.CAPApplicationSpec{
					Provider: v1alpha1.BTPTenantIdentification{
						SubDomain: subDomain,
						TenantId:  tenantId,
					},
					BTP: v1alpha1.BTP{},
					DomainRefs: []v1alpha1.DomainRefs{
						{
							Kind: "Domain",
							Name: "primaryDomain",
						},
						{
							Kind: "ClusterDomain",
							Name: "secondaryDomain",
						},
					},
				},
				Kind: crdType,
			}
		}

		rawBytes, err = json.Marshal(crd)
		rawBytesOld = rawBytes
		if operation == admissionv1.Update && err == nil {
			crdOld := crd
			if change == providerUpdate {
				crdOld.Spec.Provider.SubDomain = crdOld.Spec.Provider.SubDomain + "modified"
				crdOld.Spec.Provider.TenantId = crdOld.Spec.Provider.TenantId + "modified"
				rawBytesOld, err = json.Marshal(crdOld)
			} else if change == domainsUpdate {
				crd.Spec.DomainRefs = []v1alpha1.DomainRefs{}
				crd.Spec.Domains = v1alpha1.ApplicationDomains{Primary: "primaryDomain", IstioIngressGatewayLabels: []v1alpha1.NameValue{{Name: "foo", Value: "bar"}}}
				rawBytes, err = json.Marshal(crd)
			}
		}

		if operation == admissionv1.Create && change == useDomains && err == nil {
			crd.Spec.DomainRefs = []v1alpha1.DomainRefs{}
			crd.Spec.Domains = v1alpha1.ApplicationDomains{Primary: "primaryDomain", IstioIngressGatewayLabels: []v1alpha1.NameValue{{Name: "foo", Value: "bar"}}}
			rawBytes, err = json.Marshal(crd)
		}
	case v1alpha1.CAPApplicationVersionKind:
		crd := &ResponseCav{}
		if change != emptyUpdate {
			crd = &ResponseCav{
				Metadata: Metadata{
					Name:      crdName,
					Namespace: metav1.NamespaceDefault,
				},
				Spec: &v1alpha1.CAPApplicationVersionSpec{
					CAPApplicationInstance: caName,
					Workloads: []v1alpha1.WorkloadDetails{
						{
							Name:                "cap-backend",
							ConsumedBTPServices: []string{},
							DeploymentDefinition: &v1alpha1.DeploymentDetails{
								Type: v1alpha1.DeploymentCAP,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
						{
							Name:                "cap-router",
							ConsumedBTPServices: []string{},
							DeploymentDefinition: &v1alpha1.DeploymentDetails{
								Type: v1alpha1.DeploymentRouter,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
						{
							Name:                "content",
							ConsumedBTPServices: []string{},
							JobDefinition: &v1alpha1.JobDetails{
								Type: v1alpha1.JobContent,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
					},
				},
				Kind: crdType,
			}
		}
		rawBytes, err = json.Marshal(crd)
		rawBytesOld = rawBytes
		if operation == admissionv1.Update && err == nil && change != noUpdate {
			crdOld := crd

			switch change {
			case appInstanceUpdate:
				crdOld.Spec.CAPApplicationInstance = crdOld.Spec.CAPApplicationInstance + "modified"
			case registrySecretsUpdate:
				crdOld.Spec.RegistrySecrets = append(crdOld.Spec.RegistrySecrets, "newSecret")
			case consumedBTPServicesUpdate:
				crdOld.Spec.Workloads[0].ConsumedBTPServices = append(crdOld.Spec.Workloads[0].ConsumedBTPServices, "newService")
			case versionUpdate:
				crdOld.Spec.Version = crdOld.Spec.Version + "modified"
			case imageUpdate:
				crdOld.Spec.Workloads[0].DeploymentDefinition.Image = crdOld.Spec.Workloads[0].DeploymentDefinition.Image + "modified"
			}
			rawBytesOld, err = json.Marshal(crdOld)
		}
	case v1alpha1.CAPTenantKind:
		crd := &ResponseCat{}
		if change != emptyUpdate {
			crd = &ResponseCat{
				Metadata: Metadata{
					Name:      crdName,
					Namespace: metav1.NamespaceDefault,
					Labels: map[string]string{
						LabelTenantType: ProviderTenantType,
					},
				},
				Spec: &v1alpha1.CAPTenantSpec{
					CAPApplicationInstance: caName,
				},
				Status: &v1alpha1.CAPTenantStatus{
					State: v1alpha1.CAPTenantStateReady,
				},
				Kind: crdType,
			}
		}
		rawBytes, err = json.Marshal(crd)
		rawBytesOld = rawBytes
		if (operation == admissionv1.Update || operation == admissionv1.Delete) && err == nil {
			crdOld := crd
			if change == appInstanceUpdate {
				crdOld.Spec.CAPApplicationInstance = crdOld.Spec.CAPApplicationInstance + "modified"
				rawBytesOld, err = json.Marshal(crdOld)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	if operation != admissionv1.Delete {
		admissionReview.Request.Object.Raw = rawBytes
	}

	if operation != admissionv1.Create && operation != admissionv1.Connect {
		admissionReview.Request.OldObject.Raw = rawBytesOld
	}

	return admissionReview, nil
}

func TestInvalidRequest(t *testing.T) {
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}

	recorder := httptest.NewRecorder()
	admissionReview := admissionv1.AdmissionReview{}
	bytesRequest, err := json.Marshal(admissionReview)
	if err != nil {
		t.Fatal("marshal error")
	}
	request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))

	wh.Validate(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatal("Error was not recorded correctly")
	}
}

func TestSideCar(t *testing.T) {
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}

	tests := []struct {
		sideCarEnv string
	}{
		{
			sideCarEnv: "true",
		},
		{
			sideCarEnv: "false",
		},
		{
			sideCarEnv: "invalid",
		},
	}
	for _, test := range tests {
		t.Run("Testing SideCarEnv value "+test.sideCarEnv, func(t *testing.T) {
			os.Setenv(SideCarEnv, test.sideCarEnv)

			recorder := httptest.NewRecorder()

			admissionReview := admissionv1.AdmissionReview{}
			bytesRequest, err := json.Marshal(admissionReview)
			if err != nil {
				t.Fatal("marshal error")
			}
			request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))

			wh.Validate(recorder, request)
			file, err := os.ReadFile(os.TempDir() + RequestPath)
			if err != nil {
				t.Error("Side car file read error")
			}
			json.Unmarshal(file, &admissionReview)

			if admissionReview.Request != nil || admissionReview.Response != nil {
				t.Fatal("Invalid admission review with http error")
			}

			if test.sideCarEnv == "invalid" {
				if recorder.Code != http.StatusInternalServerError {
					t.Fatal("Error was not recorded correctly")
				}
			} else if recorder.Code != http.StatusBadRequest {
				t.Fatal("Error was not recorded correctly")
			}

			os.Unsetenv(SideCarEnv)
		})
	}
}

func TestEmptyResources(t *testing.T) {
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}
	tests := []struct {
		operation admissionv1.Operation
		crdType   string
	}{
		{
			operation: admissionv1.Update,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Delete,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Update,
			crdType:   v1alpha1.CAPTenantKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPTenantKind,
		},
		{
			operation: admissionv1.Delete,
			crdType:   v1alpha1.CAPTenantKind,
		},
		{
			operation: admissionv1.Update,
			crdType:   v1alpha1.CAPApplicationKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPApplicationKind,
		},
		{
			operation: admissionv1.Delete,
			crdType:   v1alpha1.CAPApplicationKind,
		},
	}
	for _, test := range tests {
		t.Run("Testing admission review for empty (invalid) "+test.crdType+" resource with operation "+string(test.operation), func(t *testing.T) {
			crdName := cavName
			if test.crdType == v1alpha1.CAPTenantKind {
				crdName = catName
			} else {
				crdName = caName
			}

			request, recorder := getHttpRequest(test.operation, test.crdType, crdName, emptyUpdate, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, _ := io.ReadAll(recorder.Body)
			universalDeserializer.Decode(bytes, nil, &admissionReview)
			if admissionReview.Request != nil || admissionReview.Response != nil {
				t.Fatal("Invalid admission review with http error")
			}
			if recorder.Code != http.StatusInternalServerError {
				t.Fatal("Error was not recorded correctly")
			}
		})
	}
}

func TestUnhandledType(t *testing.T) {
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}

	tests := []struct {
		operation admissionv1.Operation
		crdType   string
	}{
		{
			operation: admissionv1.Update,
		},
		{
			operation: admissionv1.Create,
		},
		{
			operation: admissionv1.Delete,
		},
		{
			operation: admissionv1.Connect,
		},
	}
	for _, test := range tests {
		t.Run("Testing unhandled resource type validity for operation "+string(test.operation), func(t *testing.T) {

			request, recorder := getHttpRequest(test.operation, "Unhandled", "unhandled", noUpdate, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, _ := io.ReadAll(recorder.Body)
			universalDeserializer.Decode(bytes, nil, &admissionReview)
			if !admissionReview.Response.Allowed || admissionReview.Response.UID != uid {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCavAndCatValidity(t *testing.T) {
	// valid CAPApplication
	Ca := createCaCRO()
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(Ca),
	}

	tests := []struct {
		operation    admissionv1.Operation
		crdType      string
		backlogItems []string
	}{
		{
			operation: admissionv1.Update,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Delete,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Connect,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Update,
			crdType:   v1alpha1.CAPTenantKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPTenantKind,
		},
		{
			operation:    admissionv1.Delete,
			crdType:      v1alpha1.CAPTenantKind,
			backlogItems: []string{"ERP4SMEPREPWORKAPPPLAT-2520"},
		},
		{
			operation: admissionv1.Connect,
			crdType:   v1alpha1.CAPTenantKind,
		},
	}
	for _, test := range tests {
		nameParts := []string{"Testing " + test.crdType + " validity for operation " + string(test.operation) + "; "}
		testName := strings.Join(append(nameParts, test.backlogItems...), " ")
		t.Run(testName, func(t *testing.T) {
			crdName := cavName
			if test.crdType == v1alpha1.CAPTenantKind {
				crdName = catName
			}

			request, recorder := getHttpRequest(test.operation, test.crdType, crdName, noUpdate, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}

			universalDeserializer.Decode(bytes, nil, &admissionReview)

			var errorMessage string
			if test.operation == admissionv1.Delete && test.crdType == v1alpha1.CAPTenantKind {
				errorMessage = fmt.Sprintf("%s provider %s %s cannot be deleted when a consistent %s %s exists. Delete the %s instead to delete all tenants", InvalidationMessage, admissionReview.Kind, catName, v1alpha1.CAPApplicationKind, Ca.Name, v1alpha1.CAPApplicationKind)
				if admissionReview.Response.Allowed ||
					admissionReview.Response.UID != uid ||
					admissionReview.APIVersion != apiVersion ||
					admissionReview.Response.Result.Message != errorMessage {
					t.Fatal("validation response error")
				}
			} else if !admissionReview.Response.Allowed ||
				admissionReview.Response.UID != uid ||
				admissionReview.APIVersion != apiVersion ||
				admissionReview.Response.Result != nil {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCavAndCatInvalidityNoApp(t *testing.T) {
	// no CAPApplication
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}

	tests := []struct {
		operation admissionv1.Operation
		crdType   string
	}{
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPApplicationVersionKind,
		},
		{
			operation: admissionv1.Create,
			crdType:   v1alpha1.CAPTenantKind,
		},
	}
	for _, test := range tests {
		t.Run("Testing "+test.crdType+" invalidity with no CAPApp for operation "+string(test.operation), func(t *testing.T) {
			crdName := cavName
			if test.crdType == v1alpha1.CAPTenantKind {
				crdName = catName
			}

			request, recorder := getHttpRequest(test.operation, test.crdType, crdName, noUpdate, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReview)
			if admissionReview.Response.Allowed ||
				admissionReview.Response.UID != uid ||
				admissionReview.APIVersion != apiVersion ||
				admissionReview.Response.Result.Message != fmt.Sprintf("%s %s no valid %s found for: %s.%s", InvalidationMessage, admissionReview.Kind, v1alpha1.CAPApplicationKind, metav1.NamespaceDefault, crdName) {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCavAndCatInvaliditySpecChange(t *testing.T) {
	// valid CAPApplication
	Ca := createCaCRO()
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(Ca),
	}

	tests := []struct {
		operation  admissionv1.Operation
		crdType    string
		changeType updateType
	}{
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPApplicationVersionKind,
			changeType: appInstanceUpdate,
		},
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPApplicationVersionKind,
			changeType: registrySecretsUpdate,
		},
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPApplicationVersionKind,
			changeType: consumedBTPServicesUpdate,
		},
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPApplicationVersionKind,
			changeType: versionUpdate,
		},
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPApplicationVersionKind,
			changeType: imageUpdate,
		},
		{
			operation:  admissionv1.Update,
			crdType:    v1alpha1.CAPTenantKind,
			changeType: appInstanceUpdate,
		},
	}
	for _, test := range tests {
		t.Run("Testing "+test.crdType+" invalidity with CAPApp instance change for operation "+string(test.operation), func(t *testing.T) {
			crdName := cavName
			if test.crdType == v1alpha1.CAPTenantKind {
				crdName = catName
			}

			request, recorder := getHttpRequest(test.operation, test.crdType, crdName, test.changeType, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}

			universalDeserializer.Decode(bytes, nil, &admissionReview)

			expectedMessage := fmt.Sprintf("%s %s spec cannot be modified for: %s.%s", InvalidationMessage, admissionReview.Kind, metav1.NamespaceDefault, crdName)
			if test.crdType == v1alpha1.CAPTenantKind {
				expectedMessage = fmt.Sprintf("%s %s capApplicationInstance value cannot be modified for: %s.%s", InvalidationMessage, admissionReview.Kind, metav1.NamespaceDefault, crdName)
			}

			if admissionReview.Response.Allowed ||
				admissionReview.Response.UID != uid ||
				admissionReview.APIVersion != apiVersion ||
				admissionReview.Response.Result.Message != expectedMessage {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCaValidity(t *testing.T) {
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(),
	}
	tests := []struct {
		operation  admissionv1.Operation
		tenantType string
	}{
		{
			operation: admissionv1.Delete,
		},
		{
			operation: admissionv1.Update,
		},
		{
			operation: admissionv1.Create,
		},
		{
			operation: admissionv1.Connect,
		},
	}
	for _, test := range tests {
		t.Run("Testing CAPApplication validity for operation "+string(test.operation), func(t *testing.T) {
			request, recorder := getHttpRequest(test.operation, v1alpha1.CAPApplicationKind, caName, noUpdate, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReview)

			if !admissionReview.Response.Allowed ||
				admissionReview.Response.UID != uid ||
				admissionReview.APIVersion != apiVersion ||
				admissionReview.Response.Result != nil {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCaInvalidity(t *testing.T) {
	tests := []struct {
		operation admissionv1.Operation
		update    updateType
	}{
		{
			operation: admissionv1.Update,
			update:    providerUpdate,
		},
		{
			operation: admissionv1.Update,
			update:    domainsUpdate,
		},
		{
			operation: admissionv1.Create,
			update:    useDomains,
		},
	}
	for _, test := range tests {
		t.Run("Testing CAPApplication invalidity for operation "+string(test.operation), func(t *testing.T) {
			var crdObjects []runtime.Object

			wh := &WebhookHandler{
				CrdClient: fakeCrdClient.NewSimpleClientset(crdObjects...),
			}

			request, recorder := getHttpRequest(test.operation, v1alpha1.CAPApplicationKind, caName, test.update, t)

			wh.Validate(recorder, request)

			admissionReview := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReview)

			var errorMessage string
			if test.update == providerUpdate {
				errorMessage = fmt.Sprintf("%s %s provider details cannot be changed for: %s.%s", InvalidationMessage, admissionReview.Kind, metav1.NamespaceDefault, caName)
			} else if test.update == domainsUpdate || test.update == useDomains {
				errorMessage = fmt.Sprintf("%s %s domains are deprecated. Use domainRefs instead in: %s.%s", InvalidationMessage, admissionReview.Kind, metav1.NamespaceDefault, caName)
			}

			if admissionReview.Response.Allowed ||
				admissionReview.Response.UID != uid ||
				admissionReview.APIVersion != apiVersion ||
				admissionReview.Response.Result.Message != errorMessage {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCavInvalidity(t *testing.T) {
	Ca := createCaCRO()
	wh := &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(Ca),
	}
	tests := []struct {
		operation                           admissionv1.Operation
		duplicateWorkloadName               bool
		invalidDeploymentType               bool
		invalidJobType                      bool
		onlyOneCAPTypeAllowed               bool
		onlyOneRouterTypeAllowed            bool
		duplicatePortName                   bool
		duplicatePortNumber                 bool
		routerDestNameCAPChk                bool
		routerDestNameRouterChk             bool
		customTenantOpWithoutSequence       bool
		tenantOperationSequenceInvalid      bool
		invalidWorkloadInTenantOpSeq        bool
		missingTenantOpInSeqProvisioning    bool
		missingTenantOpInSeqUpgrade         bool
		missingTenantOpInSeqDeprovisioning  bool
		multipleContentJobsWithNoOrder      bool
		missingContentJobinContentJobs      bool
		invalidJobinContentJobs             bool
		invalidWorkloadName                 bool
		longWorkloadName                    bool
		onlyServiceWorkloads                bool
		serviceExposureWrongWorkloadName    bool
		duplicateSubDomainInServiceExposure bool
		backlogItems                        []string
	}{
		{
			operation:             admissionv1.Create,
			duplicateWorkloadName: true,
			backlogItems:          []string{"ERP4SMEPREPWORKAPPPLAT-2338"},
		},
		{
			operation:             admissionv1.Create,
			invalidDeploymentType: true,
			backlogItems:          []string{"ERP4SMEPREPWORKAPPPLAT-2338"},
		},
		{
			operation:      admissionv1.Create,
			invalidJobType: true,
			backlogItems:   []string{"ERP4SMEPREPWORKAPPPLAT-2338"},
		},
		{
			operation:             admissionv1.Create,
			onlyOneCAPTypeAllowed: true,
			backlogItems:          []string{"ERP4SMEPREPWORKAPPPLAT-2338"},
		},
		{
			operation:                admissionv1.Create,
			onlyOneRouterTypeAllowed: true,
			backlogItems:             []string{"ERP4SMEPREPWORKAPPPLAT-2338"},
		},
		{
			operation:         admissionv1.Create,
			duplicatePortName: true,
			backlogItems:      []string{"ERP4SMEPREPWORKAPPPLAT-2339"},
		},
		{
			operation:           admissionv1.Create,
			duplicatePortNumber: true,
			backlogItems:        []string{"ERP4SMEPREPWORKAPPPLAT-2339"},
		},
		{
			operation:            admissionv1.Create,
			routerDestNameCAPChk: true,
			backlogItems:         []string{"ERP4SMEPREPWORKAPPPLAT-2339"},
		},
		{
			operation:               admissionv1.Create,
			routerDestNameRouterChk: true,
			backlogItems:            []string{"ERP4SMEPREPWORKAPPPLAT-2339"},
		},
		{
			operation:                     admissionv1.Create,
			customTenantOpWithoutSequence: true,
			backlogItems:                  []string{"ERP4SMEPREPWORKAPPPLAT-2405"},
		},
		{
			operation:                      admissionv1.Create,
			tenantOperationSequenceInvalid: true,
			backlogItems:                   []string{"ERP4SMEPREPWORKAPPPLAT-2405"},
		},
		{
			operation:                    admissionv1.Create,
			invalidWorkloadInTenantOpSeq: true,
			backlogItems:                 []string{"ERP4SMEPREPWORKAPPPLAT-2405"},
		},
		{
			operation:                        admissionv1.Create,
			missingTenantOpInSeqProvisioning: true,
			backlogItems:                     []string{"ERP4SMEPREPWORKAPPPLAT-3537"},
		},
		{
			operation:                   admissionv1.Create,
			missingTenantOpInSeqUpgrade: true,
			backlogItems:                []string{"ERP4SMEPREPWORKAPPPLAT-3537"},
		},
		{
			operation:                          admissionv1.Create,
			missingTenantOpInSeqDeprovisioning: true,
			backlogItems:                       []string{"ERP4SMEPREPWORKAPPPLAT-3537"},
		},
		{
			operation:                      admissionv1.Create,
			multipleContentJobsWithNoOrder: true,
			backlogItems:                   []string{"ERP4SMEPREPWORKAPPPLAT-4351"},
		},
		{
			operation:                      admissionv1.Create,
			missingContentJobinContentJobs: true,
			backlogItems:                   []string{"ERP4SMEPREPWORKAPPPLAT-4351"},
		},
		{
			operation:               admissionv1.Create,
			invalidJobinContentJobs: true,
			backlogItems:            []string{"ERP4SMEPREPWORKAPPPLAT-4351"},
		},
		{
			operation:           admissionv1.Create,
			invalidWorkloadName: true,
			backlogItems:        []string{},
		},
		{
			operation:        admissionv1.Create,
			longWorkloadName: true,
			backlogItems:     []string{},
		},
		{
			operation:            admissionv1.Create,
			onlyServiceWorkloads: true,
			backlogItems:         []string{},
		},
		{
			operation:                        admissionv1.Create,
			serviceExposureWrongWorkloadName: true,
			backlogItems:                     []string{},
		},
		{
			operation:                           admissionv1.Create,
			duplicateSubDomainInServiceExposure: true,
			backlogItems:                        []string{},
		},
	}
	for _, test := range tests {
		nameParts := []string{"Testing CAPApplicationversion invalidity for operation " + string(test.operation) + "; "}
		testName := strings.Join(append(nameParts, test.backlogItems...), " ")
		t.Run(testName, func(t *testing.T) {
			admissionReview, err := createAdmissionRequest(test.operation, v1alpha1.CAPApplicationVersionKind, caName, noUpdate)
			if err != nil {
				t.Fatal("admission review error")
			}

			crd := &ResponseCav{
				Metadata: Metadata{
					Name:      cavName,
					Namespace: metav1.NamespaceDefault,
				},
				Spec: &v1alpha1.CAPApplicationVersionSpec{
					CAPApplicationInstance: caName,
					Workloads: []v1alpha1.WorkloadDetails{
						{
							Name:                "cap-backend",
							ConsumedBTPServices: []string{},
							DeploymentDefinition: &v1alpha1.DeploymentDetails{
								Type: v1alpha1.DeploymentCAP,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
						{
							Name:                "cap-router",
							ConsumedBTPServices: []string{},
							DeploymentDefinition: &v1alpha1.DeploymentDetails{
								Type: v1alpha1.DeploymentRouter,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
						{
							Name:                "content",
							ConsumedBTPServices: []string{},
							JobDefinition: &v1alpha1.JobDetails{
								Type: v1alpha1.JobContent,
								CommonDetails: v1alpha1.CommonDetails{
									Image: "foo",
								},
							},
						},
					},
				},
				Kind: v1alpha1.CAPApplicationVersionKind,
			}

			if test.duplicateWorkloadName == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "cap-backend",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentAdditional,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.invalidDeploymentType == true {
				crd.Spec.Workloads[0].DeploymentDefinition.Type = "invalid"
			} else if test.invalidJobType == true {
				crd.Spec.Workloads[2].JobDefinition.Type = "invalid"
			} else if test.onlyOneCAPTypeAllowed == true {
				// add additional workload of type CAP
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "cap-backend-2",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentCAP,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.onlyOneRouterTypeAllowed == true {
				// add additional workload of type Router
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "cap-router-2",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentRouter,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.duplicatePortName == true {
				crd.Spec.Workloads[0].DeploymentDefinition.Ports = []v1alpha1.Ports{
					{Name: "port-1", RouterDestinationName: "port-1-dest", Port: 4000}, {Name: "port-1", Port: 4004},
				}
			} else if test.duplicatePortNumber == true {
				crd.Spec.Workloads[0].DeploymentDefinition.Ports = []v1alpha1.Ports{
					{Name: "port-1", RouterDestinationName: "port-1-dest", Port: 4000}, {Name: "port-2", Port: 4000},
				}
			} else if test.routerDestNameCAPChk == true {
				crd.Spec.Workloads[0].DeploymentDefinition.Ports = []v1alpha1.Ports{
					{Name: "port-1", Port: 4000}, {Name: "port-2", Port: 4004},
				}
			} else if test.routerDestNameRouterChk == true {
				crd.Spec.Workloads[1].DeploymentDefinition.Ports = []v1alpha1.Ports{
					{Name: "port-1", RouterDestinationName: "port-1-dest", Port: 4000}, {Name: "port-2", Port: 4004},
				}
			} else if test.customTenantOpWithoutSequence == true {
				// add workload of type custom tenant operation
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "custom-tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobCustomTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.tenantOperationSequenceInvalid == true {
				// add workload of type custom tenant operation and tenant operation
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "custom-tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobCustomTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				crd.Spec.TenantOperations = &v1alpha1.TenantOperations{
					Provisioning: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "custom-tenant-operation"},
					},
					Deprovisioning: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "custom-tenant-operation"},
					},
					Upgrade: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "custom-tenant-operation"},
					},
				}
			} else if test.invalidWorkloadInTenantOpSeq == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				crd.Spec.TenantOperations = &v1alpha1.TenantOperations{
					Provisioning: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
					},
					Deprovisioning: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "tenant-operation"},
					},
					Upgrade: []v1alpha1.TenantOperationWorkloadReference{
						{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
					},
				}
			} else if test.missingTenantOpInSeqProvisioning == true || test.missingTenantOpInSeqUpgrade == true || test.missingTenantOpInSeqDeprovisioning == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "custom-tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobCustomTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				if test.missingTenantOpInSeqProvisioning == true {
					crd.Spec.TenantOperations = &v1alpha1.TenantOperations{
						Provisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "custom-tenant-operation"},
						},
						Deprovisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
						Upgrade: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
					}
				} else if test.missingTenantOpInSeqUpgrade == true {
					crd.Spec.TenantOperations = &v1alpha1.TenantOperations{
						Provisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
						Deprovisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
						Upgrade: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "custom-tenant-operation"},
						},
					}
				} else if test.missingTenantOpInSeqDeprovisioning == true {
					crd.Spec.TenantOperations = &v1alpha1.TenantOperations{
						Provisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
						Deprovisioning: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "custom-tenant-operation"},
						},
						Upgrade: []v1alpha1.TenantOperationWorkloadReference{
							{WorkloadName: "tenant-operation"}, {WorkloadName: "custom-tenant-operation"},
						},
					}
				}
			} else if test.multipleContentJobsWithNoOrder == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "content-2",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobContent,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.missingContentJobinContentJobs == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "content-2",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobContent,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
				crd.Spec.ContentJobs = append(crd.Spec.ContentJobs, "content")
			} else if test.invalidJobinContentJobs == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "content-2",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobContent,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
				crd.Spec.ContentJobs = append(crd.Spec.ContentJobs, "content", "content-2", "dummy")
			} else if test.invalidWorkloadName == true {
				crd.Spec.Workloads[0].Name = "WrongWorkloadName"
			} else if test.longWorkloadName == true {
				crd.Spec.Workloads[0].Name = "extralongworkloadnamecontainingmorethan64characters"
			} else if test.onlyServiceWorkloads == true {
				for _, workload := range crd.Spec.Workloads {
					if workload.DeploymentDefinition != nil {
						workload.DeploymentDefinition.Type = v1alpha1.DeploymentService
					}
				}

				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "custom-tenant-operation",
					ConsumedBTPServices: []string{},
					JobDefinition: &v1alpha1.JobDetails{
						Type: v1alpha1.JobCustomTenantOperation,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})
			} else if test.serviceExposureWrongWorkloadName == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "service-1",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentService,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				crd.Spec.ServiceExposures = append(crd.Spec.ServiceExposures, v1alpha1.ServiceExposure{
					SubDomain: "svc-subdomain",
					Routes: []v1alpha1.Route{
						{
							WorkloadName: "wrong-name",
							Port:         4004,
							Path:         "abc",
						},
					},
				})
			} else if test.duplicateSubDomainInServiceExposure == true {
				crd.Spec.Workloads = append(crd.Spec.Workloads, v1alpha1.WorkloadDetails{
					Name:                "service-1",
					ConsumedBTPServices: []string{},
					DeploymentDefinition: &v1alpha1.DeploymentDetails{
						Type: v1alpha1.DeploymentService,
						CommonDetails: v1alpha1.CommonDetails{
							Image: "foo",
						},
					},
				})

				crd.Spec.ServiceExposures = append(crd.Spec.ServiceExposures, v1alpha1.ServiceExposure{
					SubDomain: "svc-subdomain",
					Routes: []v1alpha1.Route{
						{
							WorkloadName: "service-1",
							Port:         4004,
							Path:         "api",
						},
					},
				})

				crd.Spec.ServiceExposures = append(crd.Spec.ServiceExposures, v1alpha1.ServiceExposure{
					SubDomain: "svc-subdomain",
					Routes: []v1alpha1.Route{
						{
							WorkloadName: "service-1",
							Port:         4004,
						},
					},
				})
			}

			rawBytes, _ := json.Marshal(crd)
			admissionReview.Request.Object.Raw = rawBytes
			bytesRequest, err := json.Marshal(admissionReview)
			if err != nil {
				t.Fatal("marshal error")
			}
			request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))
			recorder := httptest.NewRecorder()

			wh.Validate(recorder, request)

			admissionReviewRes := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReviewRes)

			var errorMessage string
			if test.duplicateWorkloadName == true {
				errorMessage = fmt.Sprintf("%s %s duplicate workload name: cap-backend", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.invalidDeploymentType == true {
				errorMessage = fmt.Sprintf("%s %s invalid deployment definition type. Only supported - CAP, Router, Additional and Service", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.invalidJobType == true {
				errorMessage = fmt.Sprintf("%s %s invalid job definition type. Only supported - Content, TenantOperation and CustomTenantOperation", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.onlyOneCAPTypeAllowed == true {
				errorMessage = fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.DeploymentCAP, 2, v1alpha1.DeploymentCAP)
			} else if test.onlyOneRouterTypeAllowed == true {
				errorMessage = fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.DeploymentRouter, 2, v1alpha1.DeploymentRouter)
			} else if test.duplicatePortName == true {
				errorMessage = fmt.Sprintf("%s %s duplicate port name: port-1 in workload - cap-backend", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.duplicatePortNumber == true {
				errorMessage = fmt.Sprintf("%s %s duplicate port number: 4000 in workload - cap-backend", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.routerDestNameCAPChk == true {
				errorMessage = fmt.Sprintf("%s %s routerDestinationName not defined in port configuration of workload - cap-backend", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.routerDestNameRouterChk == true {
				errorMessage = fmt.Sprintf("%s %s routerDestinationName should not be defined for workload of type Router - cap-router", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.customTenantOpWithoutSequence == true {
				errorMessage = fmt.Sprintf("%s %s - If a jobDefinition of type CustomTenantOperation is part of the workloads, then spec.tenantOperations must be specified", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.tenantOperationSequenceInvalid == true {
				errorMessage = fmt.Sprintf("%s %s workload tenant operation tenant-operation is not specified in spec.tenantOperations", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.invalidWorkloadInTenantOpSeq == true {
				errorMessage = fmt.Sprintf("%s %s custom-tenant-operation specified in spec.tenantOperations is not a valid workload of type TenantOperation or CustomTenantOperation", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.missingTenantOpInSeqProvisioning == true {
				errorMessage = fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.provisioning", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.missingTenantOpInSeqUpgrade == true {
				errorMessage = fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.upgrade", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.missingTenantOpInSeqDeprovisioning == true {
				errorMessage = fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.deprovisioning", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.multipleContentJobsWithNoOrder == true {
				errorMessage = fmt.Sprintf("%s %s if there are more than one content job, contentJobs should be defined", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.missingContentJobinContentJobs == true {
				errorMessage = fmt.Sprintf("%s %s content job content-2 is not specified as part of ContentJobs", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.invalidJobinContentJobs == true {
				errorMessage = fmt.Sprintf("%s %s job dummy specified as part of ContentJobs is not a valid content job", InvalidationMessage, v1alpha1.CAPApplicationVersionKind)
			} else if test.invalidWorkloadName == true {
				errorMessage = fmt.Sprintf("%s %s Invalid workload name: %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, "WrongWorkloadName")
			} else if test.longWorkloadName == true {
				errorMessage = fmt.Sprintf("%s %s Derived service name: %s for workload %s will exceed 63 character limit. Adjust CAPApplicationVerion resource name or the workload name accordingly", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, crd.Name+"-"+"extralongworkloadnamecontainingmorethan64characters"+"-svc", "extralongworkloadnamecontainingmorethan64characters")
			} else if test.onlyServiceWorkloads == true {
				errorMessage = fmt.Sprintf(TenantOpJobWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.JobTenantOperation, v1alpha1.JobCustomTenantOperation, v1alpha1.DeploymentService)
			} else if test.serviceExposureWrongWorkloadName == true {
				errorMessage = fmt.Sprintf(ServiceExposureWorkloadNameErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, crd.Spec.ServiceExposures[0].Routes[0].WorkloadName, crd.Spec.ServiceExposures[0].SubDomain)
			} else if test.duplicateSubDomainInServiceExposure == true {
				errorMessage = fmt.Sprintf(DuplicateServiceExposureSubDomainErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, crd.Spec.ServiceExposures[0].SubDomain)
			}

			if admissionReviewRes.Response.Allowed || admissionReviewRes.Response.Result.Message != errorMessage {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestCtoutInvalidity(t *testing.T) {
	tests := []struct {
		operation    admissionv1.Operation
		labelPresent bool
	}{
		{
			operation:    admissionv1.Create,
			labelPresent: true,
		},
		{
			operation:    admissionv1.Create,
			labelPresent: false,
		},
		{
			operation:    admissionv1.Update,
			labelPresent: true,
		},
		{
			operation:    admissionv1.Update,
			labelPresent: false,
		},
	}
	for _, test := range tests {
		t.Run("Testing CAPTenantOutput invalidity for operation "+string(test.operation), func(t *testing.T) {
			var crdObjects []runtime.Object

			wh := &WebhookHandler{
				CrdClient: fakeCrdClient.NewSimpleClientset(crdObjects...),
			}

			ctout := &ResponseCtout{
				Metadata: Metadata{
					Name:      "some-ctout",
					Namespace: metav1.NamespaceDefault,
					Labels:    map[string]string{},
				},
				Spec: &v1alpha1.CAPTenantOutputSpec{
					SubscriptionCallbackData: `{"supportUsers":[{"name":"user_t1", "email":"usert1@foo.com"},{"name":"user_t2", "email":"usert2@foo.com"}]}`,
				},
				Kind: v1alpha1.CAPApplicationVersionKind,
			}

			if test.labelPresent {
				ctout.Labels[LabelTenantId] = "some-tenant-id"
			}

			admissionReview, err := createAdmissionRequest(test.operation, v1alpha1.CAPTenantOutputKind, ctout.Name, noUpdate)
			if err != nil {
				t.Fatal("admission review error")
			}

			rawBytes, _ := json.Marshal(ctout)
			admissionReview.Request.Object.Raw = rawBytes
			bytesRequest, err := json.Marshal(admissionReview)
			if err != nil {
				t.Fatal("marshal error")
			}
			request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))
			recorder := httptest.NewRecorder()

			wh.Validate(recorder, request)

			admissionReviewRes := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReviewRes)

			if test.labelPresent {
				if admissionReviewRes.Response.Allowed || admissionReviewRes.Response.Result.Message != fmt.Sprintf("%s %s label %s on CAP tenant output %s does not contain a valid tenant ID", InvalidationMessage, v1alpha1.CAPTenantOutputKind, LabelTenantId, "some-ctout") {
					t.Fatal("validation response error")
				}
			} else {
				if admissionReviewRes.Response.Allowed || admissionReviewRes.Response.Result.Message != fmt.Sprintf("%s %s label %s missing on CAP tenant output %s", InvalidationMessage, v1alpha1.CAPTenantOutputKind, LabelTenantId, "some-ctout") {
					t.Fatal("validation response error")
				}
			}
		})
	}
}

func TestClusterDomainInvalidity(t *testing.T) {
	tests := []struct {
		operation              admissionv1.Operation
		duplicateClusterDomain bool
		duplicateDomain        bool
	}{
		{
			operation:              admissionv1.Create,
			duplicateClusterDomain: true,
		},
		{
			operation:       admissionv1.Create,
			duplicateDomain: true,
		},
	}
	for _, test := range tests {
		t.Run("Testing ClusterDomain invalidity during "+string(test.operation), func(t *testing.T) {
			clusterDomain := &v1alpha1.ClusterDomain{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-domain",
				},
				Spec: v1alpha1.DomainSpec{
					Domain: "foo-cluster-domain.com",
					IngressSelector: map[string]string{
						"app":   "istio-ingressgateway",
						"istio": "ingressgateway",
					},
				},
			}
			domain := &v1alpha1.Domain{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "domain",
					Namespace: metav1.NamespaceDefault,
				},
				Spec: v1alpha1.DomainSpec{
					Domain: "foo-domain.com",
					IngressSelector: map[string]string{
						"app":   "istio-ingressgateway",
						"istio": "ingressgateway",
					},
				},
			}

			wh := &WebhookHandler{
				CrdClient: fakeCrdClient.NewSimpleClientset(clusterDomain, domain),
			}

			admissionReview, err := createAdmissionRequest(test.operation, v1alpha1.ClusterDomainKind, clusterDomain.Name, noUpdate)
			if err != nil {
				t.Fatal("admission review error")
			}

			var clusterDomainDup *v1alpha1.ClusterDomain
			clusterDomainDup = clusterDomain.DeepCopy()
			if test.duplicateClusterDomain {
				clusterDomainDup.Name = clusterDomainDup.Name + "-duplicate"
			} else if test.duplicateDomain {
				clusterDomainDup.Name = clusterDomainDup.Name + "-duplicate"
				clusterDomainDup.Spec.Domain = domain.Spec.Domain
			}

			rawBytes, _ := json.Marshal(clusterDomainDup)
			admissionReview.Request.Object.Raw = rawBytes
			bytesRequest, err := json.Marshal(admissionReview)
			if err != nil {
				t.Fatal("marshal error")
			}
			request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))
			recorder := httptest.NewRecorder()

			wh.Validate(recorder, request)

			admissionReviewRes := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReviewRes)

			var errorMessage string
			if test.duplicateClusterDomain {
				errorMessage = fmt.Sprintf("%s %s %s already exist with domain %s", InvalidationMessage, v1alpha1.ClusterDomainKind, clusterDomain.Name, clusterDomain.Spec.Domain)
			} else if test.duplicateDomain {
				errorMessage = fmt.Sprintf("%s %s %s already exist in namespace %s with domain %s", InvalidationMessage, v1alpha1.DomainKind, domain.Name, domain.Namespace, domain.Spec.Domain)
			}

			if admissionReviewRes.Response.Allowed || admissionReviewRes.Response.Result.Message != errorMessage {
				t.Fatal("validation response error")
			}
		})
	}
}

func TestDomainInvalidity(t *testing.T) {
	tests := []struct {
		operation              admissionv1.Operation
		duplicateClusterDomain bool
		duplicateDomain        bool
	}{
		{
			operation:              admissionv1.Create,
			duplicateClusterDomain: true,
		},
		{
			operation:       admissionv1.Create,
			duplicateDomain: true,
		},
	}
	for _, test := range tests {
		t.Run("Testing Domain invalidity during "+string(test.operation), func(t *testing.T) {
			clusterDomain := &v1alpha1.ClusterDomain{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-domain",
				},
				Spec: v1alpha1.DomainSpec{
					Domain: "foo-cluster-domain.com",
					IngressSelector: map[string]string{
						"app":   "istio-ingressgateway",
						"istio": "ingressgateway",
					},
				},
			}
			domain := &v1alpha1.Domain{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "domain",
					Namespace: metav1.NamespaceDefault,
				},
				Spec: v1alpha1.DomainSpec{
					Domain: "foo-domain.com",
					IngressSelector: map[string]string{
						"app":   "istio-ingressgateway",
						"istio": "ingressgateway",
					},
				},
			}

			wh := &WebhookHandler{
				CrdClient: fakeCrdClient.NewSimpleClientset(clusterDomain, domain),
			}

			admissionReview, err := createAdmissionRequest(test.operation, v1alpha1.ClusterDomainKind, clusterDomain.Name, noUpdate)
			if err != nil {
				t.Fatal("admission review error")
			}

			var domainDup *v1alpha1.Domain
			domainDup = domain.DeepCopy()
			if test.duplicateClusterDomain {
				domainDup.Name = domainDup.Name + "-duplicate"
				domainDup.Spec.Domain = clusterDomain.Spec.Domain
			} else if test.duplicateDomain {
				domainDup.Name = domainDup.Name + "-duplicate"
			}

			rawBytes, _ := json.Marshal(domainDup)
			admissionReview.Request.Object.Raw = rawBytes
			bytesRequest, err := json.Marshal(admissionReview)
			if err != nil {
				t.Fatal("marshal error")
			}
			request := httptest.NewRequest(http.MethodGet, "/validate", bytes.NewBuffer(bytesRequest))
			recorder := httptest.NewRecorder()

			wh.Validate(recorder, request)

			admissionReviewRes := admissionv1.AdmissionReview{}
			bytes, err := io.ReadAll(recorder.Body)
			if err != nil {
				t.Fatal("io read error")
			}
			universalDeserializer.Decode(bytes, nil, &admissionReviewRes)

			var errorMessage string
			if test.duplicateClusterDomain {
				errorMessage = fmt.Sprintf("%s %s %s already exist with domain %s", InvalidationMessage, v1alpha1.ClusterDomainKind, clusterDomain.Name, clusterDomain.Spec.Domain)
			} else if test.duplicateDomain {
				errorMessage = fmt.Sprintf("%s %s %s already exist in namespace %s with domain %s", InvalidationMessage, v1alpha1.DomainKind, domain.Name, domain.Namespace, domain.Spec.Domain)
			}

			if admissionReviewRes.Response.Allowed || admissionReviewRes.Response.Result.Message != errorMessage {
				t.Fatal("validation response error")
			}
		})
	}
}
