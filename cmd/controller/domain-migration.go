package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"slices"
	"strings"

	certManager "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	gardenerCert "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	gardenerDNS "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	istio "istio.io/client-go/pkg/clientset/versioned"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/klog/v2"
)

const (
	LabelBTPApplicationIdentifierHash = "sme.sap.com/btp-app-identifier-hash"
	LabelOwnerIdentifierHash          = "sme.sap.com/owner-identifier-hash"
	LabelMigratedToDomainRefsFromCA   = "sme.sap.com/migrated-to-domain-refs-From-CA"
)

const dryRun = false

func migrateToDomainRefs(crdClient versioned.Interface, istioClient istio.Interface, gardenerCertificateClient gardenerCert.Interface, certManagerCertificateClient certManager.Interface, gardenerDNSClient gardenerDNS.Interface) bool {
	klog.Info("Starting domain migration")

	caList, err := crdClient.SmeV1alpha1().CAPApplications(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.Error("Reading CAPApplication failed", err)
		return false
	}

	if len(caList.Items) == 0 {
		klog.Info("No CAPApplications found. Skipping migration.")
		return true
	}

	// [Step 1] Delete all DNS Entries
	klog.Info("Deleting DNS entries")
	if err := deleteDnsEntries(gardenerDNSClient, crdClient, caList.Items); err != nil {
		klog.Errorf("Deleting DNS entries failed %v", err)
		return false
	}
	klog.Info("Deleting DNS entries finished")

	// [Step 2] Delete all Istio Gateways
	klog.Info("Deleting Istio Gateways")
	if err := deleteIstioGateways(istioClient, caList.Items); err != nil {
		klog.Errorf("Deleting Istio Gateways failed %v", err)
		return false
	}
	klog.Info("Deleting Istio Gateways finished")

	// [Step 3] Delete all Gardener and cert-manager Certificates
	klog.Info("Deleting Gardener and cert-manager certificates")
	if err := deleteCertificates(gardenerCertificateClient, certManagerCertificateClient, caList.Items); err != nil {
		klog.Errorf("Deleting certificates failed %v", err)
		return false
	}
	klog.Info("Deleting Gardener and cert-manager certificates finished")

	// [Step 5] Create domain resource in the CAPApplication namespace for each primary domain and collect all secondary domains
	var secondaryDomainMap = make(map[string][]*v1alpha1.CAPApplication)
	for _, ca := range caList.Items {
		if ca.Spec.Domains.Primary == "" {
			klog.Infof("Skipping CAPApplication %s.%s as it has no primary domain", ca.Namespace, ca.Name)
			continue
		}
		domainName := ca.Spec.BTPAppName + "-primary"
		if err := createDomain(crdClient, domainName, ca.Spec.Domains.Primary, v1alpha1.DnsModeWildcard, &ca); err != nil {
			klog.Errorf("Creating domain %s.%s with host %s failed with error %v", domainName, ca.Namespace, ca.Spec.Domains.Primary, err)
			return false
		}

		// Add domainRef to the CAPApplication
		ca.Spec.DomainRefs = append(ca.Spec.DomainRefs, v1alpha1.DomainRefs{
			Kind: v1alpha1.DomainKind,
			Name: domainName,
		})

		// Collect all secondary domains from CAPApplications
		for _, secDom := range ca.Spec.Domains.Secondary {
			secondaryDomainMap[secDom] = append(secondaryDomainMap[secDom], &ca)
		}
	}

	// [Step 6] If there are multiple CAPApplications with the same secondary domain, create a cluster domain otherwise create a domain
	for secDom, cas := range secondaryDomainMap {
		if len(cas) == 1 {
			// find the index in the caList[0] with the same secondary domain
			secDomIndex := slices.IndexFunc(cas[0].Spec.Domains.Secondary, func(dom string) bool { return dom == secDom })
			domainName := fmt.Sprintf("%s-secondary-%d", cas[0].Spec.BTPAppName, secDomIndex)
			if err := createDomain(crdClient, domainName, secDom, v1alpha1.DnsModeSubdomain, cas[0]); err != nil {
				klog.Errorf("Creating domain %s.%s with host %s failed with error %v", domainName, cas[0].Namespace, secDom, err)
				return false
			}

			// Add domainRef to the CAPApplication
			cas[0].Spec.DomainRefs = append(cas[0].Spec.DomainRefs, v1alpha1.DomainRefs{
				Kind: v1alpha1.DomainKind,
				Name: domainName,
			})
			continue
		}

		// If there are multiple CAPApplications with the same secondary domain, create a cluster domain
		clusterDomainName := "cap-operator-domains-"
		cdom, err := createClusterDomain(crdClient, clusterDomainName, secDom, cas[0])
		if err != nil {
			klog.Errorf("Creating cluster domain %s with host %s failed with error %v", clusterDomainName, secDom, err)
			return false
		}

		// Add domainRef to all CAPApplications
		for _, ca := range cas {
			ca.Spec.DomainRefs = append(ca.Spec.DomainRefs, v1alpha1.DomainRefs{
				Kind: v1alpha1.ClusterDomainKind,
				Name: cdom.Name,
			})
		}
	}

	// [Step 7] Update the CAPApplications with the new domainRefs
	for _, ca := range caList.Items {
		if len(ca.Spec.DomainRefs) == 0 {
			continue
		}

		// Remove the old domains from the CAPApplication
		ca.Spec.Domains = v1alpha1.ApplicationDomains{}

		_, err = crdClient.SmeV1alpha1().CAPApplications(ca.Namespace).Update(context.TODO(), &ca, metav1.UpdateOptions{})
		if err != nil {
			klog.Errorf("Updating CAPApplication %s.%s with domainRefs failed: %v", ca.Namespace, ca.Name, err)
			return false
		}
	}

	klog.Info("Domain migration finished")
	return true
}

func deleteDnsEntries(gardenerDNSClient gardenerDNS.Interface, crdClient versioned.Interface, caList []v1alpha1.CAPApplication) error {
	// Delete all DNS Entries with owner CAPApplications
	for _, ca := range caList {
		ownerIdentifierHash := sha1Sum(v1alpha1.CAPApplicationKind, ca.Namespace, ca.Spec.BTPAppName)
		ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
		ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)

		klog.Infof("Deleting DNS Entries for CAPApplication %s.%s with ownerIdentifierHash %s", ca.Namespace, ca.Name, ownerIdentifierHash)

		if !dryRun {
			err := gardenerDNSClient.DnsV1alpha1().DNSEntries(metav1.NamespaceAll).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return err
			}
		}
	}

	// Delete all DNS Entries with owner CAPTenant
	catList, err := crdClient.SmeV1alpha1().CAPTenants(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, cat := range catList.Items {
		ownerIdentifierHash := sha1Sum(v1alpha1.CAPTenantKind, cat.Namespace, cat.Name)
		ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
		ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)

		klog.Infof("Deleting DNS Entries for CAPTenant %s.%s with ownerIdentifierHash %s", cat.Namespace, cat.Name, ownerIdentifierHash)

		if !dryRun {
			err := gardenerDNSClient.DnsV1alpha1().DNSEntries(metav1.NamespaceAll).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

func deleteCertificates(gardenerCertificateClient gardenerCert.Interface, certManagerCertificateClient certManager.Interface, caList []v1alpha1.CAPApplication) error {
	// Delete all Gardener Certificates with owner CAPApplications
	for _, ca := range caList {
		ownerIdentifierHash := sha1Sum(v1alpha1.CAPApplicationKind, ca.Namespace, ca.Spec.BTPAppName)
		ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
		ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)

		gardenerCerts, err := gardenerCertificateClient.CertV1alpha1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return err
		}
		klog.Infof("Deleting %d Gardener certificates for CAPApplication %s with ownerIdentifierHash %s", len(gardenerCerts.Items), ca.Name, ownerIdentifierHash)
		if !dryRun {
			for _, cert := range gardenerCerts.Items {
				// Remove the finalizer to allow deletion
				cert.Finalizers = nil
				if _, err := gardenerCertificateClient.CertV1alpha1().Certificates(cert.Namespace).Update(context.TODO(), &cert, metav1.UpdateOptions{}); err != nil {
					return err
				}
				if err := gardenerCertificateClient.CertV1alpha1().Certificates(cert.Namespace).Delete(context.TODO(), cert.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}

		certManagerCerts, err := certManagerCertificateClient.CertmanagerV1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return err
		}
		klog.Infof("Deleting %d cert-manager certificates for CAPApplication %s with ownerIdentifierHash %s", len(certManagerCerts.Items), ca.Name, ownerIdentifierHash)
		if !dryRun {
			for _, cert := range certManagerCerts.Items {
				// Remove the finalizer to allow deletion
				cert.Finalizers = nil
				if _, err := certManagerCertificateClient.CertmanagerV1().Certificates(cert.Namespace).Update(context.TODO(), &cert, metav1.UpdateOptions{}); err != nil {
					return err
				}
				if err := certManagerCertificateClient.CertmanagerV1().Certificates(cert.Namespace).Delete(context.TODO(), cert.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}

	ownerIdentifierHash := sha1Sum("CAPOperator", "OperatorDomains")
	ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
	ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)

	gardenerCertsCAPDomain, err := gardenerCertificateClient.CertV1alpha1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}
	klog.Infof("Deleting %d Gardener certificates for CAPOperator.OperatorDomains", len(gardenerCertsCAPDomain.Items))
	if !dryRun {
		for _, cert := range gardenerCertsCAPDomain.Items {
			if err := gardenerCertificateClient.CertV1alpha1().Certificates(cert.Namespace).Delete(context.TODO(), cert.Name, metav1.DeleteOptions{}); err != nil {
				return err
			}
		}
	}

	certManagerCertsCAPDomain, err := certManagerCertificateClient.CertmanagerV1().Certificates(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}
	klog.Infof("Deleting %d cert-manager certificates for CAPOperator.OperatorDomains", len(certManagerCertsCAPDomain.Items))
	if !dryRun {
		for _, cert := range certManagerCertsCAPDomain.Items {
			if err := certManagerCertificateClient.CertmanagerV1().Certificates(cert.Namespace).Delete(context.TODO(), cert.Name, metav1.DeleteOptions{}); err != nil {
				return err
			}
		}
	}

	return nil
}

func deleteIstioGateways(istioClient istio.Interface, caList []v1alpha1.CAPApplication) error {
	for _, ca := range caList {
		btpAppLabelHash := sha1Sum(ca.Spec.GlobalAccountId, ca.Spec.BTPAppName)
		btpAppLabelHashReq, _ := labels.NewRequirement(LabelBTPApplicationIdentifierHash, selection.Equals, []string{btpAppLabelHash})
		btpAppLabelHashSelector := labels.NewSelector().Add(*btpAppLabelHashReq)

		klog.Infof("Deleting Istio Gateways for CAPApplication %s with btpAppLabelHash %s", ca.Name, btpAppLabelHash)
		if !dryRun {
			err := istioClient.NetworkingV1beta1().Gateways(metav1.NamespaceAll).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: btpAppLabelHashSelector.String()})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return err
			}
		}
	}

	ownerIdentifierHash := sha1Sum("CAPOperator", "OperatorDomains")
	ownerLabelHashReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{ownerIdentifierHash})
	ownerLabelHashReqSelector := labels.NewSelector().Add(*ownerLabelHashReq)

	klog.Infof("Deleting Istio Gateways for CAPOperator.OperatorDomains")
	if !dryRun {
		err := istioClient.NetworkingV1beta1().Gateways(metav1.NamespaceAll).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: ownerLabelHashReqSelector.String()})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func createDomain(crdClient versioned.Interface, withName string, domainHost string, dnsMode v1alpha1.DNSMode, ca *v1alpha1.CAPApplication) error {
	domain := &v1alpha1.Domain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      withName,
			Namespace: ca.Namespace,
			Annotations: map[string]string{
				LabelMigratedToDomainRefsFromCA: ca.Namespace + "." + ca.Name,
			},
		},
		Spec: v1alpha1.DomainSpec{
			Domain:          domainHost,
			IngressSelector: getIngressGatewayLabels(ca),
			TLSMode:         v1alpha1.TlsModeSimple,
			DNSMode:         dnsMode,
		},
	}

	if ca.Spec.Domains.DnsTarget != "" {
		domain.Spec.DNSTarget = ca.Spec.Domains.DnsTarget
	}

	klog.Infof("Creating domain %s in namespace %s", domain.Name, domain.Namespace)
	if _, err := crdClient.SmeV1alpha1().Domains(domain.Namespace).Create(context.TODO(), domain, metav1.CreateOptions{}); err != nil && !k8sErrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func createClusterDomain(crdClient versioned.Interface, withGenerateName string, domainHost string, ca *v1alpha1.CAPApplication) (*v1alpha1.ClusterDomain, error) {
	// In case if the migration fails before updating the CAPApplication, we need to check if the cluster domain already exists
	// as we are using generateName and can't rely on the duplicate name check error like in the createDomain function
	existingCdoms, err := crdClient.SmeV1alpha1().ClusterDomains(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, cdom := range existingCdoms.Items {
		if cdom.Spec.Domain == domainHost {
			klog.Infof("Cluster domain %s already exists with host %s", cdom.Name, domainHost)
			return &cdom, nil
		}
	}

	clusterDomain := &v1alpha1.ClusterDomain{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: withGenerateName,
		},
		Spec: v1alpha1.DomainSpec{
			Domain:          domainHost,
			IngressSelector: getIngressGatewayLabels(ca),
			TLSMode:         v1alpha1.TlsModeSimple,
			DNSMode:         v1alpha1.DnsModeSubdomain,
		},
	}

	if ca.Spec.Domains.DnsTarget != "" {
		clusterDomain.Spec.DNSTarget = ca.Spec.Domains.DnsTarget
	}

	klog.Infof("Creating cluster domain with generate name %s", withGenerateName)
	cdom, err := crdClient.SmeV1alpha1().ClusterDomains(metav1.NamespaceAll).Create(context.TODO(), clusterDomain, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return cdom, nil
}

func getIngressGatewayLabels(ca *v1alpha1.CAPApplication) map[string]string {
	ingressLabels := map[string]string{}
	for _, label := range ca.Spec.Domains.IstioIngressGatewayLabels {
		ingressLabels[label.Name] = label.Value
	}
	return ingressLabels
}

func sha1Sum(source ...string) string {
	sum := sha1.Sum([]byte(strings.Join(source, "")))
	return fmt.Sprintf("%x", sum)
}
