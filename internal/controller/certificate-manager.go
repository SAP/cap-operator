/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"strings"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certManagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/labels"
)

const (
	certManagerCredentialSuffix = "cert-manager"
	gardenerCredentialSuffix    = "gardener"
)

type CertificateManager struct {
	c           *Controller
	managerType string
}

func CreateCertificateManager(c *Controller) *CertificateManager {
	return &CertificateManager{c: c, managerType: certificateManager()}
}

func (h *CertificateManager) handleCertificate(ctx context.Context, info *ManagedCertificateInfo) (err error) {
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(info.OwnerId),
	})
	certs, err := h.ListCertificates(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		return fmt.Errorf("failed to list certificates for %s: %w", info.OwnerId, err)
	}

	hash := info.Hash()

	certsForDeletion := []ManagedCertificate{}
	var (
		selectedCert ManagedCertificate
		consistent   bool
	)
	for i, cert := range certs {
		selectedCert = cert
		consistent = cert.GetAnnotations()[AnnotationResourceHash] == hash

		if !consistent && len(certs)-1 < i || (h.managerType == certManagerCertManagerIO && (cert.GetNamespace() != info.CredentialNamespace)) {
			certsForDeletion = append(certsForDeletion, cert)
		}
	}

	if len(certsForDeletion) > 0 {
		if err = h.DeleteCertificates(ctx, certsForDeletion); err != nil {
			return fmt.Errorf("failed to delete outdated certificates for %s: %w", info.OwnerId, err)
		}
	}

	if selectedCert == nil { // create
		err = h.CreateCertificate(ctx, info)
	} else if !consistent { // update
		err = h.UpdateCertificate(ctx, selectedCert, info)
	}
	return
}

func (h *CertificateManager) GetCredentialName(namespace, name string) string {
	credentialSuffix := gardenerCredentialSuffix
	if h.managerType == certManagerCertManagerIO {
		credentialSuffix = certManagerCredentialSuffix
	}
	return fmt.Sprintf("%s--%s-%s", namespace, name, credentialSuffix)
}

func (h *CertificateManager) ListCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		return h.listCertManagerCertificates(ctx, namespace, selector)
	default:
		return h.listGardenerCertificates(ctx, namespace, selector)
	}
}

func (h *CertificateManager) listGardenerCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
	certs, err := h.c.gardenerCertificateClient.CertV1alpha1().Certificates(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}
	list = []ManagedCertificate{}
	for _, cert := range certs.Items {
		list = append(list, &cert)
	}
	return
}

func (h *CertificateManager) listCertManagerCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
	certs, err := h.c.certManagerCertificateClient.CertmanagerV1().Certificates(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}
	list = []ManagedCertificate{}
	for _, cert := range certs.Items {
		list = append(list, &cert)
	}
	return
}

func (h *CertificateManager) DeleteCertificates(ctx context.Context, certs []ManagedCertificate) error {
	err := h.RemoveCertificateFinalizers(ctx, certs)
	if err != nil {
		return err
	}

	delGroup, delCtx := errgroup.WithContext(ctx)
	for i := range certs {

		delGroup.Go(func() error {
			cert := certs[i]
			switch h.managerType {
			case certManagerCertManagerIO:
				return h.c.certManagerCertificateClient.CertmanagerV1().Certificates(cert.GetNamespace()).Delete(delCtx, cert.GetName(), metav1.DeleteOptions{})
			default:
				return h.c.gardenerCertificateClient.CertV1alpha1().Certificates(cert.GetNamespace()).Delete(delCtx, cert.GetName(), metav1.DeleteOptions{})
			}
		})
	}
	if err = delGroup.Wait(); err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}
	return nil
}

func (h *CertificateManager) RemoveCertificateFinalizers(ctx context.Context, certs []ManagedCertificate) (err error) {
	updGroup, updCtx := errgroup.WithContext(ctx)
	for i := range certs {
		cert := certs[i]
		updGroup.Go(func() error {
			return h.removeManagedCertificateFinalizer(updCtx, cert)
		})
	}

	if err = updGroup.Wait(); err != nil {
		return fmt.Errorf("failed to remove finalizer from certificate: %w", err)
	}
	return
}

func (h *CertificateManager) removeManagedCertificateFinalizer(ctx context.Context, cert ManagedCertificate) error {
	var err error
	switch h.managerType {
	case certManagerCertManagerIO:
		if c, ok := cert.(*certManagerv1.Certificate); ok {
			// remove Finalizer from cert-manager Certificate
			if removeFinalizer(&c.Finalizers, FinalizerDomain) {
				_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
			}
		}
	default:
		if c, ok := cert.(*certv1alpha1.Certificate); ok {
			// remove Finalizer from gardener Certificate
			if removeFinalizer(&c.Finalizers, FinalizerDomain) {
				_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
			}
		}
	}
	return err
}

func (h *CertificateManager) UpdateCertificate(ctx context.Context, cert ManagedCertificate, info *ManagedCertificateInfo) (err error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		if c, ok := cert.(*certManagerv1.Certificate); ok {
			updateResourceAnnotation(&c.ObjectMeta, info.Hash())
			c.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", info.OwnerGeneration)
			c.Spec = info.getCertManagerCertificateSpec()
			_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
		} else {
			err = fmt.Errorf("failed to cast certificate to cert-manager type")
		}

	default:
		if c, ok := cert.(*certv1alpha1.Certificate); ok {
			updateResourceAnnotation(&c.ObjectMeta, info.Hash())
			c.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", info.OwnerGeneration)
			c.Spec = info.getGardenerCertificateSpec()
			_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
		} else {
			err = fmt.Errorf("failed to cast certificate to gardener type")
		}
	}
	return
}

func (h *CertificateManager) CreateCertificate(ctx context.Context, info *ManagedCertificateInfo) (err error) {
	mo := metav1.ObjectMeta{
		Labels: map[string]string{
			LabelOwnerIdentifierHash: sha1Sum(info.OwnerId),
			LabelOwnerGeneration:     fmt.Sprintf("%d", info.OwnerGeneration),
		},
		Annotations: map[string]string{
			AnnotationResourceHash:    info.Hash(),
			AnnotationOwnerIdentifier: info.OwnerId,
		},
		Finalizers: []string{FinalizerDomain},
	}

	// Gardener certificates are created in the namespace of the domain (or for clusterdomain in the operator namespace), as it supports creating TLS secrets in other namespaces (e.g. istio ingress namespace).
	// Cert-Manager certificates do not support this out of the box and hene we create these in the istio ingress namespace, and use the same name we pre-determine for credentials certificates.
	h.updateCertificateMetadata(&mo, info)
	switch h.managerType {
	case certManagerCertManagerIO:
		_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(mo.Namespace).Create(ctx, &certManagerv1.Certificate{
			ObjectMeta: mo,
			Spec:       info.getCertManagerCertificateSpec(),
		}, metav1.CreateOptions{})

	default:
		_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(mo.Namespace).Create(ctx, &certv1alpha1.Certificate{
			ObjectMeta: mo,
			Spec:       info.getGardenerCertificateSpec(),
		}, metav1.CreateOptions{})
	}
	return
}

func (h *CertificateManager) updateCertificateMetadata(meta *metav1.ObjectMeta, info *ManagedCertificateInfo) {
	if h.managerType == certManagerCertManagerIO {
		// cert-manager certificates are created in the istio ingress namespace, and use the credential name w/o any suffix.
		meta.Name = info.CredentialName[:strings.LastIndex(info.CredentialName, "-"+certManagerCredentialSuffix)]
		meta.Namespace = info.CredentialNamespace
	} else {
		meta.GenerateName = info.Name + "-"
		meta.Namespace = info.Namespace
	}
}

func (h *CertificateManager) IsCertificateReady(cert ManagedCertificate) (bool, error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		if c, ok := cert.(*certManagerv1.Certificate); ok {
			return isCertManagerCertReady(c)
		} else {
			return false, fmt.Errorf("failed to cast certificate to cert-manager type")
		}
	default:
		if c, ok := cert.(*certv1alpha1.Certificate); ok {
			// check for ready state
			if c.Status.State == certv1alpha1.StateError {
				return false, fmt.Errorf("%s has state %s: %s", certv1alpha1.CertificateKind, certv1alpha1.StateError, *c.Status.Message)
			} else if c.Status.State != certv1alpha1.StateReady {
				return false, nil
			}
		} else {
			return false, fmt.Errorf("failed to cast certificate to gardener type")
		}
	}
	return true, nil
}

type ManagedCertificate interface {
	GetAnnotations() map[string]string
	GetName() string
	GetNamespace() string
	GetLabels() map[string]string
}

type ManagedCertificateInfo struct {
	Domain              string
	Name                string
	Namespace           string
	CredentialName      string
	CredentialNamespace string
	OwnerId             string
	OwnerGeneration     int64
}

func (o *ManagedCertificateInfo) Hash() string {
	return sha256Sum(o.Domain, o.CredentialName, o.CredentialNamespace)
}

func (o *ManagedCertificateInfo) getGardenerCertificateSpec() certv1alpha1.CertificateSpec {
	return certv1alpha1.CertificateSpec{
		DNSNames: []string{"*." + o.Domain},
		SecretRef: &corev1.SecretReference{
			Name:      o.CredentialName,
			Namespace: o.CredentialNamespace,
		},
	}
}

func (o *ManagedCertificateInfo) getCertManagerCertificateSpec() certManagerv1.CertificateSpec {
	return certManagerv1.CertificateSpec{
		DNSNames:   []string{"*." + o.Domain},
		SecretName: o.CredentialName,
		IssuerRef: certManagermetav1.ObjectReference{
			// TODO: make this configurable
			Kind: certManagerv1.ClusterIssuerKind,
			Name: "cluster-ca",
		},
	}
}

func isCertManagerCertReady(certificate *certManagerv1.Certificate) (bool, error) {
	var readyCond *certManagerv1.CertificateCondition
	for _, cond := range certificate.Status.Conditions {
		if cond.Type == certManagerv1.CertificateConditionReady {
			readyCond = &cond
			break
		}
	}
	// check for ready state
	if readyCond == nil || readyCond.Status == certManagermetav1.ConditionUnknown {
		return false, nil
	} else if readyCond.Status == certManagermetav1.ConditionFalse {
		return false, fmt.Errorf("%s not ready: %s %s", certManagerv1.CertificateKind, certv1alpha1.StateError, readyCond.Message)
	}
	return true, nil
}

func areCertificatesReady(ctx context.Context, c *Controller, ownerId string) (ready bool, err error) {
	// create a label selector to filter certificates by owner identifier hash
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})

	h := CreateCertificateManager(c)
	certs, err := h.ListCertificates(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		return false, fmt.Errorf("failed to list certificates: %w", err)
	}

	for i := range certs {
		cert := certs[i]
		var ready bool
		if ready, err = h.IsCertificateReady(cert); err != nil || !ready {
			return ready, err
		}
	}

	return true, nil
}
