/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certManagerFake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	certManagerScheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	gardenercertv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	gardenercertfake "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned/fake"
	gardenercertscheme "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned/scheme"
	gardenerdnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	gardenerdnsfake "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned/fake"
	gardenerdnsscheme "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned/scheme"
	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	promopFake "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/fake"
	promopScheme "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/scheme"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	copfake "github.com/sap/cap-operator/pkg/client/clientset/versioned/fake"
	smeScheme "github.com/sap/cap-operator/pkg/client/clientset/versioned/scheme"
	istiometav1alpha1 "istio.io/api/meta/v1alpha1"
	istionetworkingv1 "istio.io/api/networking/v1"
	istionwv1 "istio.io/client-go/pkg/apis/networking/v1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	istioscheme "istio.io/client-go/pkg/clientset/versioned/scheme"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
)

var gvrKindMap map[string]string = map[string]string{
	"dnsentries.dns.gardener.cloud/v1alpha1":      "DNSEntry",
	"captenantoutputs.sme.sap.com/v1alpha1":       "CAPTenantOutput",
	"captenantoperations.sme.sap.com/v1alpha1":    "CAPTenantOperation",
	"captenants.sme.sap.com/v1alpha1":             "CAPTenant",
	"capapplications.sme.sap.com/v1alpha1":        "CAPApplication",
	"capapplicationversions.sme.sap.com/v1alpha1": "CAPApplicationVersion",
	"servicemonitors.monitoring.coreos.com/v1":    "ServiceMonitor",
}

// adds fixed suffix "gen" to newly created objects with generateName
var generateNameCreateHandler k8stesting.ReactionFunc = func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
	create := action.(k8stesting.CreateAction)
	obj := create.GetObject()
	mo, ok := obj.(metav1.Object)
	if ok {
		if mo.GetGenerateName() != "" && mo.GetName() == "" {
			mo.SetName(mo.GetGenerateName() + "gen")
		}
	}

	return false, obj, nil
}

func getErrorReactorWithResources(t *testing.T, items []ResourceAction) k8stesting.ReactionFunc {
	actionItems := items
	return func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		gvr := action.GetResource()

		var getObject = func() runtime.Object {
			var obj runtime.Object
			switch action.GetVerb() {
			case "create":
				obj = action.(k8stesting.CreateAction).GetObject()
			case "update":
				obj = action.(k8stesting.UpdateAction).GetObject()
			}
			return obj
		}

		for _, i := range actionItems {
			if i.Group == gvr.Group && i.Version == gvr.Version && i.Resource == gvr.Resource {
				if i.Verb == "*" || i.Verb == action.GetVerb() {
					if i.Namespace == "*" || i.Namespace == action.GetNamespace() {
						errMsg := fmt.Sprintf("mocked api error (%s.%s/%s)", gvr.Resource, gvr.Group, gvr.Version)
						if i.Name == "*" {
							return true, nil, errors.New(errMsg)
						}
						if o := getObject(); o != nil {
							if mo, ok := o.(metav1.Object); ok {
								if mo.GetName() == i.Name {
									return true, nil, errors.New(errMsg)
								}
							}
						}
						var moName string
						switch action.GetVerb() {
						case "delete":
							moName = action.(k8stesting.DeleteAction).GetName()
						case "get":
							moName = action.(k8stesting.GetAction).GetName()
						}
						if moName != "" && moName == i.Name {
							return true, nil, errors.New(errMsg)
						}
					}
				}
			}
		}

		return false, getObject(), nil
	}
}

// resets the timestamps for know CRO status conditions (so that they can be compared later)
var removeStatusTimestampHandler k8stesting.ReactionFunc = func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
	update := action.(k8stesting.UpdateAction)
	obj := update.GetObject()
	if update.GetSubresource() == "status" {
		var adjustConditions = func(conditions []metav1.Condition) []metav1.Condition {
			adjustedConditions := []metav1.Condition{}
			for _, condition := range conditions {
				zeroTime, _ := time.Parse(time.RFC3339, "0001-01-01T00:00:00Z")
				condition.LastTransitionTime = metav1.NewTime(zeroTime)
				adjustedConditions = append(adjustedConditions, condition)
			}
			return adjustedConditions
		}

		switch cro := obj.(type) {
		case *v1alpha1.CAPApplication:
			cro.Status.Conditions = adjustConditions(cro.Status.Conditions)
		case *v1alpha1.CAPApplicationVersion:
			cro.Status.Conditions = adjustConditions(cro.Status.Conditions)
		case *v1alpha1.CAPTenant:
			cro.Status.Conditions = adjustConditions(cro.Status.Conditions)
		case *v1alpha1.CAPTenantOperation:
			cro.Status.Conditions = adjustConditions(cro.Status.Conditions)
		}
	}

	return false, obj, nil
}

type FakeClientSetConstraint interface {
	*k8sfake.Clientset | *gardenerdnsfake.Clientset | *gardenercertfake.Clientset | *copfake.Clientset | *istiofake.Clientset | *certManagerFake.Clientset
	Tracker() k8stesting.ObjectTracker
}

func getKindFromGVR(gvr schema.GroupVersionResource) string {
	return gvrKindMap[fmt.Sprintf("%s.%s/%s", gvr.Resource, gvr.Group, gvr.Version)]
}

// the returned ReactionFunction mocks delete-collection action by selecting based on provided labels and deleting individual items. It does not support field selectors.
func getDeleteCollectionHandler[T FakeClientSetConstraint](t *testing.T, client T) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		dca := action.(k8stesting.DeleteCollectionAction)
		lreqs, err := labels.ParseToRequirements(dca.GetListRestrictions().Labels.String())
		if err != nil {
			return true, nil, err
		}
		o, err := client.Tracker().List(dca.GetResource(), dca.GetResource().GroupVersion().WithKind(getKindFromGVR(dca.GetResource())), dca.GetNamespace())
		if err != nil {
			return true, nil, err
		}
		// list, ok := o.(*gardenerdnsv1alpha1.DNSEntryList)
		tmp := reflect.ValueOf(o).Elem().FieldByName("Items")
		for i := 0; i < tmp.Len(); i++ {
			item := tmp.Index(i)
			mo, ok := item.Addr().Interface().(metav1.Object)
			if !ok {
				t.Errorf("expected list item to contain metadata")
			}
			t.Logf("%s.%s", mo.GetNamespace(), mo.GetName())
			matchFailed := false
			for _, lreq := range lreqs {
				if !lreq.Matches(labels.Set(mo.GetLabels())) {
					matchFailed = true
					break
				}
			}
			if !matchFailed {
				err = client.Tracker().Delete(dca.GetResource(), dca.GetNamespace(), mo.GetName())
				if err != nil {
					return true, nil, err
				}
			}
		}
		return true, nil, nil
	}
}

func addForDiscovery(c *k8stesting.Fake, resources []schema.GroupVersionResource) {
	m := map[string][]schema.GroupVersionResource{}
	for i := range resources {
		r := resources[i]
		gv := fmt.Sprintf("%s/%s", r.Group, r.Version)
		if v, ok := m[gv]; ok {
			v = append(v, r)
		} else {
			m[gv] = []schema.GroupVersionResource{r}
		}
	}
	for k, v := range m {
		apiResources := []metav1.APIResource{}
		for i := range v {
			apiResources = append(apiResources, metav1.APIResource{Name: v[i].Resource, Kind: getKindFromGVR(v[i])})
		}
		c.Resources = append(c.Resources, &metav1.APIResourceList{GroupVersion: k, APIResources: apiResources})
	}
}

func initializeControllerForReconciliationTests(t *testing.T, items []ResourceAction, discoverResources []schema.GroupVersionResource) *Controller {
	// add schemes for various client sets
	smeScheme.AddToScheme(scheme.Scheme)
	gardenercertscheme.AddToScheme(scheme.Scheme)
	gardenerdnsscheme.AddToScheme(scheme.Scheme)
	istioscheme.AddToScheme(scheme.Scheme)
	certManagerScheme.AddToScheme(scheme.Scheme)
	promopScheme.AddToScheme(scheme.Scheme)

	coreClient := k8sfake.NewSimpleClientset()
	if len(discoverResources) > 0 {
		addForDiscovery(&coreClient.Fake, discoverResources)
	}
	copClient := copfake.NewSimpleClientset()
	istioClient := istiofake.NewSimpleClientset()
	gardenerCertClient := gardenercertfake.NewSimpleClientset()
	gardenerDNSClient := gardenerdnsfake.NewSimpleClientset()
	certManagerClient := certManagerFake.NewSimpleClientset()
	promopClient := promopFake.NewSimpleClientset()

	copClient.PrependReactor("create", "*", generateNameCreateHandler)
	copClient.PrependReactor("update", "*", removeStatusTimestampHandler)
	copClient.PrependReactor("delete-collection", "*", getDeleteCollectionHandler(t, copClient))
	copClient.PrependReactor("*", "*", getErrorReactorWithResources(t, items))

	istioClient.PrependReactor("create", "*", generateNameCreateHandler)
	istioClient.PrependReactor("delete-collection", "*", getDeleteCollectionHandler(t, istioClient))
	istioClient.PrependReactor("*", "*", getErrorReactorWithResources(t, items))

	coreClient.PrependReactor("create", "*", generateNameCreateHandler)
	coreClient.PrependReactor("create", "*", generateNameCreateHandler)
	coreClient.PrependReactor("*", "*", getErrorReactorWithResources(t, items))

	gardenerDNSClient.PrependReactor("create", "*", generateNameCreateHandler)
	gardenerDNSClient.PrependReactor("*", "*", getErrorReactorWithResources(t, items))
	gardenerDNSClient.PrependReactor("delete-collection", "*", getDeleteCollectionHandler(t, gardenerDNSClient))

	gardenerCertClient.PrependReactor("create", "*", generateNameCreateHandler)
	gardenerCertClient.PrependReactor("*", "*", getErrorReactorWithResources(t, items))
	gardenerCertClient.PrependReactor("delete-collection", "*", getDeleteCollectionHandler(t, gardenerDNSClient))

	c := NewController(coreClient, copClient, istioClient, gardenerCertClient, certManagerClient, gardenerDNSClient, promopClient)
	c.eventRecorder = events.NewFakeRecorder(10)
	return c
}

type TestData struct {
	// test case description for logging
	description string
	// file paths to initial resources to be loaded before tests
	initialResources []string
	// file path to expected resources to compare after test
	expectedResources string
	// expect reconciliation error
	expectError bool
	// expect resource is not found
	expectResourceNotFound bool
	// expect items to be requeued
	expectedRequeue map[int][]NamespacedResourceKey
	// attempts
	attempts int
	// mock errors during the following resource modifications
	mockErrorForResources []ResourceAction
	// add resources for discovery API
	discoverResources []schema.GroupVersionResource
	// relevant backlog items (link for traceability)
	backlogItems []string
}

type ResourceAction struct {
	Verb      string
	Group     string
	Version   string
	Resource  string
	Name      string
	Namespace string
}

type TestDataType string

const (
	TestDataTypeInitial  TestDataType = "initial"
	TestDataTypeExpected TestDataType = "expected"
)

func eventDrain(ctx context.Context, c *Controller, t *testing.T) {
	select {
	case <-ctx.Done():
		return
	case e := <-c.eventRecorder.(*events.FakeRecorder).Events:
		t.Log(e)
	}
}

func reconcileTestItem(ctx context.Context, t *testing.T, item QueueItem, data TestData) (err error) {
	// run inside a test sub-context to maintain test case name with reference to backlog items
	t.Run(strings.Join(append([]string{data.description}, data.backlogItems...), " "), func(t *testing.T) {
		// Deregister metrics
		defer deregisterMetrics()

		c := initializeControllerForReconciliationTests(t, data.mockErrorForResources, data.discoverResources)
		go eventDrain(ctx, c, t)

		// load initial data
		processTestData(t, c, data, TestDataTypeInitial)

		var requeue *ReconcileResult
		switch item.Key {
		case ResourceCAPApplication:
			requeue, err = c.reconcileCAPApplication(ctx, item, data.attempts)
		case ResourceCAPApplicationVersion:
			requeue, err = c.reconcileCAPApplicationVersion(ctx, item, data.attempts)
		case ResourceCAPTenant:
			requeue, err = c.reconcileCAPTenant(ctx, item, data.attempts)
		case ResourceCAPTenantOperation:
			requeue, err = c.reconcileCAPTenantOperation(ctx, item, data.attempts)
		// case ResourceOperatorDomains:
		// 	err = c.reconcileOperatorDomains(ctx, item, data.attempts)
		default:
			t.Error("unidentified queue item for testing")
		}

		if err != nil && !data.expectError {
			t.Error(err.Error())
		}
		if data.expectError && err == nil {
			t.Error("expected error during reconciliation")
		}

		if cmpErr := verifyItemsForRequeue(data.expectedRequeue, requeue); cmpErr != nil {
			t.Error(cmpErr.Error())
		}

		// load expected data and compare
		if data.expectedResources != "" {
			processTestData(t, c, data, TestDataTypeExpected)
		} else if !data.expectResourceNotFound && err == nil { // when a resource is not found --> we simply skip reconciliation w/o errors
			t.Error("no expected resources provided (no error from reconciliation)")
		}
	})

	return err
}

func verifyItemsForRequeue(expected map[int][]NamespacedResourceKey, result *ReconcileResult) error {
	if result == nil && expected == nil {
		return nil
	}
	if (result == nil || result.requeueResources == nil) && expected != nil {
		return errors.New("expected items for requeue, found none")
	}
	if result != nil && expected == nil {
		return errors.New("did not expect items for requeue")
	}
	for rid, ev := range expected {
		if len(ev) == 0 {
			continue
		}
		av, ok := result.requeueResources[rid]
		if !ok {
			return fmt.Errorf("expected items for requeue of type %s", KindMap[rid])
		}
		avm := convertRequeueItemSliceToMap(av)
		for _, i := range ev {
			k := fmt.Sprintf("%s.%s", i.Namespace, i.Name)
			if _, ok := avm[k]; !ok {
				return fmt.Errorf("expected item %s of type %s for requeue", k, KindMap[rid])
			}
			delete(avm, k)
		}
		if len(avm) > 0 {
			return fmt.Errorf("did not expect the following items of type %s to be requeued: %s", KindMap[rid], getComaSeparatedKeys(avm, nil))
		}
		delete(result.requeueResources, rid)
	}
	if len(result.requeueResources) > 0 {
		return fmt.Errorf("did not expect the following item types to be requeued: %s", getComaSeparatedKeys(result.requeueResources, func(i int) string { return KindMap[i] }))
	}
	return nil
}

func getComaSeparatedKeys[K cmp.Ordered, T any](m map[K]T, stringer func(key K) string) string {
	s := []string{}
	for k := range m {
		var n string
		if stringer == nil {
			n = fmt.Sprintf("%v", k)
		} else {
			n = stringer(k)
		}
		s = append(s, n)
	}
	return strings.Join(s, ", ")
}

func convertRequeueItemSliceToMap(s []RequeueItem) map[string]struct{} {
	m := map[string]struct{}{}
	for _, i := range s {
		m[fmt.Sprintf("%s.%s", i.resourceKey.Namespace, i.resourceKey.Name)] = struct{}{}
	}
	return m
}

func processTestData(t *testing.T, c *Controller, data TestData, dataType TestDataType) {
	files := make([]string, 0)
	if dataType == TestDataTypeInitial {
		files = append(files, data.initialResources...)
	} else {
		files = append(files, data.expectedResources)
	}

	var wg sync.WaitGroup

	var processFile = func(file string) {
		defer wg.Done()

		resources, err := readYAMLResourcesFromFile(file)
		if err != nil {
			t.Error(err.Error())
		}
		for i := range resources {
			if dataType == TestDataTypeInitial {
				err = addInitialObjectToStore(resources[i], c)
			} else {
				err = compareExpectedWithStore(t, resources[i], c)
			}
			if err != nil {
				t.Error(err.Error())
			}
		}
	}

	for _, f := range files {
		wg.Add(1)
		go processFile(f)
	}
	wg.Wait()
}

func readYAMLResourcesFromFile(file string) ([][]byte, error) {
	i, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	resources := [][]byte{}
	fileContents := string(i)
	splits := strings.Split(fileContents, "---")
	for _, part := range splits {
		if part == "\n" || part == "" {
			continue
		}
		resources = append(resources, []byte(part))
	}
	return resources, nil
}

func addInitialObjectToStore(resource []byte, c *Controller) error {
	decoder := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decoder(resource, nil, nil)
	if err != nil {
		return err
	}

	switch obj.(type) {
	case *corev1.Secret, *corev1.Pod, *corev1.Namespace, *corev1.Service:
		fakeClient, ok := c.kubeClient.(*k8sfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		switch obj.(type) {
		case *corev1.Secret:
			err = c.kubeInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(obj)
		case *corev1.Pod:
			err = c.kubeInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(obj)
		case *corev1.Namespace:
			err = c.kubeInformerFactory.Core().V1().Namespaces().Informer().GetIndexer().Add(obj)
		case *corev1.Service:
			err = c.kubeInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(obj)
		}
	case *appsv1.Deployment:
		fakeClient, ok := c.kubeClient.(*k8sfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		err = c.kubeInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(obj)
	case *batchv1.Job:
		fakeClient, ok := c.kubeClient.(*k8sfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		err = c.kubeInformerFactory.Batch().V1().Jobs().Informer().GetIndexer().Add(obj)
	case *gardenercertv1alpha1.Certificate:
		fakeClient, ok := c.gardenerCertificateClient.(*gardenercertfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		err = c.gardenerCertInformerFactory.Cert().V1alpha1().Certificates().Informer().GetIndexer().Add(obj)
	case *certManagerv1.Certificate:
		fakeClient, ok := c.certManagerCertificateClient.(*certManagerFake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		err = c.certManagerInformerFactory.Certmanager().V1().Certificates().Informer().GetIndexer().Add(obj)
	case *gardenerdnsv1alpha1.DNSEntry:
		fakeClient, ok := c.gardenerDNSClient.(*gardenerdnsfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		err = c.gardenerDNSInformerFactory.Dns().V1alpha1().DNSEntries().Informer().GetIndexer().Add(obj)
	case *istionwv1.Gateway, *istionwv1.VirtualService, *istionwv1.DestinationRule:
		fakeClient, ok := c.istioClient.(*istiofake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		metaObj, ok := getMetaObject(obj)
		if !ok {
			return fmt.Errorf("could not type cast event object to meta object")
		}
		switch obj.(type) {
		case *istionwv1.VirtualService:
			fakeClient.Tracker().Create(schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"}, obj, metaObj.GetNamespace())
			err = c.istioInformerFactory.Networking().V1().VirtualServices().Informer().GetIndexer().Add(obj)
		case *istionwv1.Gateway:
			fakeClient.Tracker().Create(schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "gateways"}, obj, metaObj.GetNamespace())
			err = c.istioInformerFactory.Networking().V1().Gateways().Informer().GetIndexer().Add(obj)
		case *istionwv1.DestinationRule:
			fakeClient.Tracker().Create(schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"}, obj, metaObj.GetNamespace())
			err = c.istioInformerFactory.Networking().V1().DestinationRules().Informer().GetIndexer().Add(obj)
		}
	case *v1alpha1.CAPApplication, *v1alpha1.CAPApplicationVersion, *v1alpha1.CAPTenant, *v1alpha1.CAPTenantOperation:
		fakeClient, ok := c.crdClient.(*copfake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
		switch obj.(type) {
		case *v1alpha1.CAPApplication:
			err = c.crdInformerFactory.Sme().V1alpha1().CAPApplications().Informer().GetIndexer().Add(obj)
		case *v1alpha1.CAPApplicationVersion:
			err = c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Informer().GetIndexer().Add(obj)
		case *v1alpha1.CAPTenant:
			err = c.crdInformerFactory.Sme().V1alpha1().CAPTenants().Informer().GetIndexer().Add(obj)
		case *v1alpha1.CAPTenantOperation:
			err = c.crdInformerFactory.Sme().V1alpha1().CAPTenantOperations().Informer().GetIndexer().Add(obj)
		}
	case *monv1.ServiceMonitor:
		fakeClient, ok := c.promClient.(*promopFake.Clientset)
		if !ok {
			return fmt.Errorf("controller is not using a fake clientset")
		}
		fakeClient.Tracker().Add(obj)
	default:
		return fmt.Errorf("unknown object type")
	}

	return err
}

func compareExpectedWithStore(t *testing.T, resource []byte, c *Controller) error {
	decoder := scheme.Codecs.UniversalDeserializer().Decode
	expected, gvk, err := decoder(resource, nil, nil)
	if err != nil {
		return err
	}

	mo, ok := expected.(metav1.Object)
	if !ok {
		return fmt.Errorf("expected object is not a meta object")
	}

	var actual runtime.Object
	switch expected.(type) {
	case *corev1.Secret:
		actual, err = c.kubeClient.(*k8sfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("secrets"), mo.GetNamespace(), mo.GetName())
	case *corev1.Service:
		actual, err = c.kubeClient.(*k8sfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("services"), mo.GetNamespace(), mo.GetName())
	case *batchv1.Job:
		actual, err = c.kubeClient.(*k8sfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("jobs"), mo.GetNamespace(), mo.GetName())
	case *appsv1.Deployment:
		actual, err = c.kubeClient.(*k8sfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("deployments"), mo.GetNamespace(), mo.GetName())
	case *networkingv1.NetworkPolicy:
		actual, err = c.kubeClient.(*k8sfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("networkpolicies"), mo.GetNamespace(), mo.GetName())
	case *gardenercertv1alpha1.Certificate:
		actual, err = c.gardenerCertificateClient.(*gardenercertfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("certificates.cert.gardener.cloud"), mo.GetNamespace(), mo.GetName())
	case *certManagerv1.Certificate:
		actual, err = c.certManagerCertificateClient.(*certManagerFake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("certificates.cert.gardener.cloud"), mo.GetNamespace(), mo.GetName())
	case *gardenerdnsv1alpha1.DNSEntry:
		actual, err = c.gardenerDNSClient.(*gardenerdnsfake.Clientset).Tracker().Get(gvk.GroupVersion().WithResource("dnsentries"), mo.GetNamespace(), mo.GetName())
	case *istionwv1.Gateway, *istionwv1.VirtualService, *istionwv1.DestinationRule:
		fakeClient := c.istioClient.(*istiofake.Clientset)
		switch expected.(type) {
		case *istionwv1.VirtualService:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("virtualservices"), mo.GetNamespace(), mo.GetName())
		case *istionwv1.DestinationRule:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("destinationrules"), mo.GetNamespace(), mo.GetName())
		case *istionwv1.Gateway:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("gateways"), mo.GetNamespace(), mo.GetName())
		}
	case *v1alpha1.CAPApplication, *v1alpha1.CAPApplicationVersion, *v1alpha1.CAPTenant, *v1alpha1.CAPTenantOperation:
		fakeClient := c.crdClient.(*copfake.Clientset)
		switch expected.(type) {
		case *v1alpha1.CAPApplication:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("capapplications"), mo.GetNamespace(), mo.GetName())
		case *v1alpha1.CAPApplicationVersion:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("capapplicationversions"), mo.GetNamespace(), mo.GetName())
		case *v1alpha1.CAPTenant:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("captenants"), mo.GetNamespace(), mo.GetName())
		case *v1alpha1.CAPTenantOperation:
			actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("captenantoperations"), mo.GetNamespace(), mo.GetName())
		}
	case *monv1.ServiceMonitor:
		fakeClient := c.promClient.(*promopFake.Clientset)
		actual, err = fakeClient.Tracker().Get(gvk.GroupVersion().WithResource("servicemonitors"), mo.GetNamespace(), mo.GetName())
	default:
		return fmt.Errorf("unknown expected object type")
	}

	if err == nil {
		compareResourceFields(actual, expected, t, gvk.Kind, mo.GetNamespace(), mo.GetName())
	} else {
		t.Error(err.Error())
	}

	return err
}

func compareResourceFields(actual runtime.Object, expected runtime.Object, t *testing.T, kind string, namespace string, name string) {
	if diff := gocmp.Diff(
		actual, expected,
		gocmp.FilterPath(func(p gocmp.Path) bool {
			// NOTE: do not compare the type metadata as this is not guaranteed to be filled from the fake client
			return p.String() == "TypeMeta"
		}, gocmp.Ignore()),
		gocmp.FilterPath(func(p gocmp.Path) bool {
			// Ignore relevant Unexported fields introduced recently by istio in Spec
			ps := p.String()
			return ps == "Spec" || strings.HasPrefix(ps, "Spec.")
		}, cmpopts.IgnoreUnexported(
			istionetworkingv1.PortSelector{},
			istionetworkingv1.Destination{},
			istionetworkingv1.HTTPRouteDestination{},
			istionetworkingv1.StringMatch{},
			istionetworkingv1.HTTPMatchRequest{},
			istionetworkingv1.HTTPRoute{},
			istionetworkingv1.VirtualService{},
			istionetworkingv1.Server{},
			istionetworkingv1.Port{},
			istionetworkingv1.DestinationRule{},
			istionetworkingv1.TrafficPolicy{},
			istionetworkingv1.LoadBalancerSettings{},
			istionetworkingv1.LoadBalancerSettings_ConsistentHashLB{},
			istionetworkingv1.LoadBalancerSettings_ConsistentHashLB_HTTPCookie{},
			durationpb.Duration{},
		)),
		gocmp.FilterPath(func(p gocmp.Path) bool {
			// Ignore relevant Unexported fields introduced recently by istio in Status
			ps := p.String()
			return ps == "Status" || strings.HasPrefix(ps, "Status.")
		}, cmpopts.IgnoreUnexported(
			istiometav1alpha1.IstioStatus{},
		)),
	); diff != "" {
		t.Errorf("expected and actual resource differs for %s %s.%s", kind, namespace, name)
		t.Error(diff)
	}
}
