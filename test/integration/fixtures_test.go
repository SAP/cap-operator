//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This file contains builders for the dummy resources exercised by the integration
// suite. Objects are parameterised by namespace so that each test runs in isolation.
// The shapes mirror the fixtures under internal/controller/testdata but are trimmed to
// the minimum the controller needs to react.

const (
	// BTP service (instance) names referenced by workloads via consumedBTPServices.
	svcXSUAA          = "cap-uaa"
	svcServiceManager = "cap-service-manager"
	svcSaaSRegistry   = "cap-saas-registry"
)

// btpSecretNames returns the Secret names backing the app's BTP services, derived from
// the app name so that parallel tests in different namespaces never collide.
func btpSecretNames(appName string) map[string]string {
	return map[string]string{
		svcXSUAA:          appName + "-uaa-bind",
		svcServiceManager: appName + "-svcman-bind",
		svcSaaSRegistry:   appName + "-saas-bind",
	}
}

// newBTPSecret builds an Opaque Secret with a minimal (empty-JSON) `credentials`
// payload, which is enough for the controller's VCAP_SERVICES generation to succeed.
func newBTPSecret(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"credentials": []byte("{}")},
	}
}

// newCAPApplication builds a minimal CAPApplication wired to the given BTP secrets.
func newCAPApplication(ns, name string, domainRefs ...v1alpha2.DomainRef) *v1alpha2.CAPApplication {
	secrets := btpSecretNames(name)
	return &v1alpha2.CAPApplication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: v1alpha2.CAPApplicationSpec{
			DomainRefs:           domainRefs,
			ProviderSubaccountId: "provider-subaccount-id",
			BTPAppName:           name,
			Provider: &v1alpha2.BTPTenantIdentification{
				SubDomain: "provider",
				TenantId:  "provider-tenant-id",
			},
			BTP: v1alpha2.BTP{
				Services: []v1alpha2.ServiceInfo{
					{Name: svcXSUAA, Secret: secrets[svcXSUAA], Class: "xsuaa"},
					{Name: svcServiceManager, Secret: secrets[svcServiceManager], Class: "service-manager"},
					{Name: svcSaaSRegistry, Secret: secrets[svcSaaSRegistry], Class: "saas-registry"},
				},
			},
		},
	}
}

// newCAPApplicationVersion builds a minimal-but-complete CAPApplicationVersion with one
// content job, one CAP server deployment, one tenant-operation job and one app-router
// deployment - mirroring internal/controller/testdata/common/capapplicationversion-v1.yaml.
func newCAPApplicationVersion(ns, name, appName string) *v1alpha2.CAPApplicationVersion {
	return &v1alpha2.CAPApplicationVersion{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: v1alpha2.CAPApplicationVersionSpec{
			CAPApplicationInstance: appName,
			Version:                "1.0.0",
			RegistrySecrets:        []string{"regcred"},
			Workloads: []v1alpha2.WorkloadDetails{
				{
					Name:                "cap-backend",
					ConsumedBTPServices: []string{svcXSUAA, svcServiceManager, svcSaaSRegistry},
					DeploymentDefinition: &v1alpha2.DeploymentDetails{
						Type:          v1alpha2.DeploymentCAP,
						CommonDetails: v1alpha2.CommonDetails{Image: "docker.repo.example/srv/server:latest"},
					},
				},
				{
					Name:                "content-job",
					ConsumedBTPServices: []string{svcXSUAA},
					JobDefinition: &v1alpha2.JobDetails{
						Type:          v1alpha2.JobContent,
						CommonDetails: v1alpha2.CommonDetails{Image: "docker.repo.example/content/content:latest"},
					},
				},
				{
					Name:                "mtx",
					ConsumedBTPServices: []string{svcXSUAA, svcServiceManager, svcSaaSRegistry},
					JobDefinition: &v1alpha2.JobDetails{
						Type:          v1alpha2.JobTenantOperation,
						CommonDetails: v1alpha2.CommonDetails{Image: "docker.repo.example/srv/server:latest"},
					},
				},
				{
					Name:                "app-router",
					ConsumedBTPServices: []string{svcXSUAA, svcSaaSRegistry},
					DeploymentDefinition: &v1alpha2.DeploymentDetails{
						Type:          v1alpha2.DeploymentRouter,
						CommonDetails: v1alpha2.CommonDetails{Image: "docker.repo.example/approuter/approuter:latest"},
					},
				},
			},
		},
	}
}

// newDomain builds a Domain using the given ingress selector. The selector must match
// the labels on the ingress gateway pod created by newIngressGatewayInfra.
func newDomain(ns, name, host string, ingressSelector map[string]string) *v1alpha2.Domain {
	return &v1alpha2.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: v1alpha2.DomainSpec{
			Domain:          host,
			IngressSelector: ingressSelector,
			TLSMode:         v1alpha2.TlsModeSimple,
			DNSMode:         v1alpha2.DnsModeWildcard,
		},
	}
}

// ingressGatewayInfra is the set of objects the controller inspects to resolve a
// Domain's ingress gateway: a pod (matched by selector), a LoadBalancer service
// annotated with the DNS target, and an EndpointSlice linking the two.
type ingressGatewayInfra struct {
	selector      map[string]string
	pod           *corev1.Pod
	service       *corev1.Service
	endpointSlice *discoveryv1.EndpointSlice
}

// newIngressGatewayInfra builds ingress discovery objects in the given namespace. The
// selector is made unique per namespace so that concurrent tests do not match each
// other's ingress pods (the controller rejects pods spread across namespaces).
func newIngressGatewayInfra(ns string) ingressGatewayInfra {
	selector := map[string]string{"app": "istio-ingressgateway", "istio-ns": ns}
	podName := "istio-ingressgateway-" + ns
	serviceName := "istio-ingressgateway"
	return ingressGatewayInfra{
		selector: selector,
		pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns, Labels: selector},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "istio-proxy", Image: "istio/proxyv2:latest"}},
			},
		},
		service: &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: ns,
				// kubernetes-native DNS target annotation (DNS_MANAGER=kubernetes).
				Annotations: map[string]string{"external-dns.alpha.kubernetes.io/hostname": "public-ingress." + ns + ".example.local"},
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeLoadBalancer,
				Selector: selector,
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		},
		endpointSlice: &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName + "-slice",
				Namespace: ns,
				Labels:    map[string]string{"kubernetes.io/service-name": serviceName},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)},
				TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: podName, Namespace: ns},
			}},
		},
	}
}

func boolPtr(b bool) *bool { return &b }
