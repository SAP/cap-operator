/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	fakeCrdClient "github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// #region setup
func newTestHandler(objects ...runtime.Object) *WebhookHandler {
	return &WebhookHandler{
		CrdClient: fakeCrdClient.NewSimpleClientset(objects...),
	}
}

func marshalJSON(obj interface{}) []byte {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return b
}

type testReader struct{}

func (tr *testReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func simulateErrorOnAPICall(clientSet *fakeCrdClient.Clientset, verb string, resource string) {
	// Simulate an error on create
	clientSet.Fake.PrependReactor(verb, resource, func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("test error for %s on %s", resource, verb)
	})
}

//#endregion

// #region tests
func TestMutate_NoBody(t *testing.T) {
	wh := newTestHandler()
	req := httptest.NewRequest("POST", "/mutate", nil)
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatal("expected 400 Bad Request, got", w.Code)
	}
}

func TestMutate_InvalidBody(t *testing.T) {
	wh := newTestHandler()
	req := httptest.NewRequest("POST", "/mutate", &testReader{})
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatal("expected 500 Internal Server Error, got", w.Code)
	}
}

func TestMutate_NonCAPApplicationKind_Allows(t *testing.T) {
	wh := newTestHandler()
	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "123",
			Kind: metav1.GroupVersionKind{Kind: "OtherKind"},
		},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != true {
		t.Fatal("expected response to be allowed")
	}
}

func TestMutate_CAPApplicationKind_Allows(t *testing.T) {
	wh := newTestHandler()
	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "123",
			Kind:      metav1.GroupVersionKind{Kind: v1alpha1.CAPApplicationKind},
			Operation: admissionv1.Update,
		},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != true {
		t.Fatal("expected response to be allowed")
	}
}

func TestMutate_ErrorOnCanMigrate(t *testing.T) {
	wh := newTestHandler()
	// Simulate an error on create
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "get", "capapplications")

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "123",
			Kind:      metav1.GroupVersionKind{Kind: v1alpha1.CAPApplicationKind},
			Operation: admissionv1.Update,
			Object: runtime.RawExtension{Raw: marshalJSON(v1alpha1.CAPApplication{
				Spec: v1alpha1.CAPApplicationSpec{
					Domains: v1alpha1.ApplicationDomains{
						Primary: "some.app.com",
					},
				},
			})},
		},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != false {
		t.Fatal("expected response to be disallowed")
	}
	if resp.Response.Result.Message != "test error for capapplications on get" {
		t.Fatalf("expected error message about CAPApplication (canMigrate), got: %s", resp.Response.Result.Message)
	}
}

func TestMutate_CAPApplicationKind_ErrorOnCreateDomain(t *testing.T) {
	wh := newTestHandler()
	// Simulate an error on create
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "create", "domains")

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "123",
			Kind:      metav1.GroupVersionKind{Kind: v1alpha1.CAPApplicationKind},
			Operation: admissionv1.Update,
			Object: runtime.RawExtension{Raw: marshalJSON(v1alpha1.CAPApplication{
				Spec: v1alpha1.CAPApplicationSpec{
					Domains: v1alpha1.ApplicationDomains{
						Primary: "some.app.com",
					},
				},
			})},
		},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != false {
		t.Fatal("expected response to be disallowed")
	}
	if resp.Response.Result.Message != "test error for domains on create" {
		t.Fatalf("expected error message about Domain creation, got: %s", resp.Response.Result.Message)
	}
}

func TestMutate_CAPApplicationKind_ErrorOnGetDomain(t *testing.T) {
	// Create a Domain object to be found by the handler
	domain := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "testns"},
		Spec:       v1alpha1.DomainSpec{Domain: "some.app.com"},
	}
	wh := newTestHandler(domain)
	// Simulate an error on create
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "list", "clusterdomains")

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "123",
			Kind:      metav1.GroupVersionKind{Kind: v1alpha1.CAPApplicationKind},
			Operation: admissionv1.Update,
			Object: runtime.RawExtension{Raw: marshalJSON(v1alpha1.CAPApplication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testca",
					Namespace: "testns",
				},
				Spec: v1alpha1.CAPApplicationSpec{
					Domains: v1alpha1.ApplicationDomains{
						Primary:   "some.app.com",
						Secondary: []string{"other.app.com"},
					},
					DomainRefs: []v1alpha1.DomainRef{
						{Kind: "Domain", Name: "d"},
						{Kind: "ClusterDomain", Name: "cd"},
					},
				},
			})},
		},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != false {
		t.Fatal("expected response to be disallowed")
	}
	if resp.Response.Result.Message != "test error for clusterdomains on list" {
		t.Fatalf("expected error message about Domain creation, got: %s", resp.Response.Result.Message)
	}
}

func TestMutateCA_SkipIfNoDomains(t *testing.T) {
	wh := newTestHandler()
	ar := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "123",
			Kind:      metav1.GroupVersionKind{Kind: v1alpha1.CAPApplicationKind},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{Raw: marshalJSON(v1alpha1.CAPApplication{
				Spec: v1alpha1.CAPApplicationSpec{
					Domains: v1alpha1.ApplicationDomains{},
				},
			})},
		},
		Response: &admissionv1.AdmissionResponse{},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wh.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("expected 200 OK, got", w.Code)
	}
	var resp admissionv1.AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed != true {
		t.Fatal("expected response to be allowed")
	}

}

func TestHandleDomain_ExistingDomain(t *testing.T) {
	// Create a Domain object to be found by the handler
	domain := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "ns"},
		Spec:       v1alpha1.DomainSpec{Domain: "foo"},
	}
	wh := newTestHandler(domain)
	ca := &v1alpha1.CAPApplication{Spec: v1alpha1.CAPApplicationSpec{}}
	err := wh.handleDomain("foo", ca, -1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(ca.Spec.DomainRefs) != 1 {
		t.Fatalf("expected 1 domain ref, got %d", len(ca.Spec.DomainRefs))
	}
}

func TestMutateCA_MigrateDomainsToDomainRefs(t *testing.T) {
	// Setup: CAPApplication with primary and secondary domains, no DomainRefs
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
		Spec: v1alpha1.CAPApplicationSpec{
			Domains: v1alpha1.ApplicationDomains{
				Primary:   "first.com",
				Secondary: []string{"second.com"},
			},
			DomainRefs: nil,
		},
	}
	// Add Domain and ClusterDomain objects to the fake client
	domain := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "testns"},
		Spec:       v1alpha1.DomainSpec{Domain: "first.com"},
	}
	clusterDomain := &v1alpha1.ClusterDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: ""},
		Spec:       v1alpha1.DomainSpec{Domain: "second.com"},
	}
	wh := newTestHandler(domain, clusterDomain)
	ar := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: marshalJSON(ca)},
		},
		Response: &admissionv1.AdmissionResponse{},
	}
	err := wh.mutateCA(ar)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should warn about migration and patch
	if len(ar.Response.Warnings) == 0 {
		t.Error("expected migration warning")
	}
}

func TestMutateCA_SkipMigrateDomainsToDomainRefs(t *testing.T) {
	// Setup: CAPApplication with primary and secondary domains, no DomainRefs
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
		Spec: v1alpha1.CAPApplicationSpec{
			Domains: v1alpha1.ApplicationDomains{
				Primary: "foo.com",
			},
			DomainRefs: []v1alpha1.DomainRef{
				{Kind: "Domain", Name: "foo"},
				{Kind: "ClusterDomain", Name: "bar"},
			},
		},
	}
	// Add Domain and ClusterDomain objects to the fake client
	domain := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "testns"},
		Spec:       v1alpha1.DomainSpec{Domain: "foo.com"},
	}
	clusterDomain := &v1alpha1.ClusterDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: ""},
		Spec:       v1alpha1.DomainSpec{Domain: "bar.com"},
	}
	wh := newTestHandler(ca, domain, clusterDomain)
	ar := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: marshalJSON(ca)},
		},
		Response: &admissionv1.AdmissionResponse{},
	}
	err := wh.mutateCA(ar)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should warn about migration and patch
	if len(ar.Response.Warnings) == 0 {
		t.Error("expected migration warning")
	}
}

func TestCanMigrate_NoExistingObject(t *testing.T) {
	wh := newTestHandler()
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
	}
	ok, err := wh.canMigrate(ca)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Error("expected canMigrate to be true when no existing object")
	}
}

func TestCanMigrate_ExistingWithDomainRefs(t *testing.T) {
	// Existing object with DomainRefs should return false
	existing := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
		Spec: v1alpha1.CAPApplicationSpec{
			DomainRefs: []v1alpha1.DomainRef{{Kind: "Domain", Name: "foo"}},
		},
	}
	wh := newTestHandler(existing)
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
	}
	ok, err := wh.canMigrate(ca)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ok {
		t.Error("expected canMigrate to be false when existing object has DomainRefs")
	}
}

func TestHandleDomain_CreatesDomainIfNotFound(t *testing.T) {
	wh := newTestHandler()
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
		Spec: v1alpha1.CAPApplicationSpec{
			Domains: v1alpha1.ApplicationDomains{
				Primary:                   "newdomain.com",
				IstioIngressGatewayLabels: []v1alpha1.NameValue{{Name: "app", Value: "istio-ingressgateway"}, {Name: "istio", Value: "ingressgateway"}},
			},
		},
	}
	err := wh.handleDomain("newdomain.com", ca, -1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(ca.Spec.DomainRefs) != 1 {
		t.Fatalf("expected 1 domain ref, got %d", len(ca.Spec.DomainRefs))
	}
	if ca.Spec.DomainRefs[0].Kind != "Domain" {
		t.Fatalf("expected DomainRef kind Domain, got %s", ca.Spec.DomainRefs[0].Kind)
	}
}

func TestHandleDomain_CreatesClusterDomainIfNotFound(t *testing.T) {
	wh := newTestHandler()
	ca := &v1alpha1.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "testca", Namespace: "testns"},
		Spec:       v1alpha1.CAPApplicationSpec{},
	}
	err := wh.handleDomain("clusterdomain.com", ca, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(ca.Spec.DomainRefs) != 1 {
		t.Fatalf("expected 1 domain ref, got %d", len(ca.Spec.DomainRefs))
	}
	if ca.Spec.DomainRefs[0].Kind != "ClusterDomain" {
		t.Fatalf("expected DomainRef kind ClusterDomain, got %s", ca.Spec.DomainRefs[0].Kind)
	}
}

func TestHandleDomain_ReturnsErrorDomain(t *testing.T) {
	wh := newTestHandler()
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "list", "domains")
	err := wh.handleDomain("domain.com", &v1alpha1.CAPApplication{}, -1)
	if err == nil {
		t.Fatalf("expected error got nil")
	}
}

func TestHandleDomain_ReturnsErrorListClusterDomain(t *testing.T) {
	wh := newTestHandler()
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "list", "clusterdomains")
	err := wh.handleDomain("domain.com", &v1alpha1.CAPApplication{}, 1)
	if err == nil {
		t.Fatalf("expected error got nil")
	}
}

func TestHandleDomain_ReturnsErrorCreateClusterDomain(t *testing.T) {
	wh := newTestHandler()
	simulateErrorOnAPICall(wh.CrdClient.(*fakeCrdClient.Clientset), "create", "clusterdomains")
	err := wh.handleDomain("domain.com", &v1alpha1.CAPApplication{}, 1)
	if err == nil {
		t.Fatalf("expected error got nil")
	}
}

func TestGetDomain_ReturnsNilIfNotFound(t *testing.T) {
	wh := newTestHandler()
	details, err := wh.getDomain("notfound.com", "ns")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if details != nil {
		t.Fatal("expected nil details for not found domain")
	}
}

//#endregion
