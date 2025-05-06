/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"

	certManagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certManagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/labels"
)

type CertificateConstraint interface {
	*certv1alpha1.Certificate | *certManagerv1.Certificate
}

type CertificateHandler struct {
	c           *Controller
	managerType string
	// ListCertificates(ctx context.Context, namespace string, selector labels.Selector) ([]*ManagedCertificate[T], error)
}

func NewCertificateHandler(c *Controller) *CertificateHandler {
	return &CertificateHandler{c: c, managerType: certificateManager()}
}

func (h *CertificateHandler) ListCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		return h.listCertManagerCertificates(ctx, namespace, selector)
	default:
		return h.listGardenerCertificates(ctx, namespace, selector)
	}
}

func (h *CertificateHandler) listGardenerCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
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

func (h *CertificateHandler) listCertManagerCertificates(ctx context.Context, namespace string, selector labels.Selector) (list []ManagedCertificate, err error) {
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

func (h *CertificateHandler) DeleteCertificates(ctx context.Context, certs []ManagedCertificate) error {
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

func (h *CertificateHandler) RemoveCertificateFinalizers(ctx context.Context, certs []ManagedCertificate) (err error) {
	updGroup, updCtx := errgroup.WithContext(ctx)
	for i := range certs {
		cert := certs[i]
		switch h.managerType {
		case certManagerCertManagerIO:
			if c, ok := cert.(*certManagerv1.Certificate); ok {
				updGroup.Go(func() error {
					var err error
					// remove Finalizer from cert-manager Certificate
					if removeFinalizer(&c.Finalizers, FinalizerDomain) {
						_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(c.Namespace).Update(updCtx, c, metav1.UpdateOptions{})
					}
					return err
				})
			}
		default:
			if c, ok := cert.(*certv1alpha1.Certificate); ok {
				updGroup.Go(func() error {
					var err error
					// remove Finalizer from gardener Certificate
					if removeFinalizer(&c.Finalizers, FinalizerDomain) {
						_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(c.Namespace).Update(updCtx, c, metav1.UpdateOptions{})
					}
					return err
				})
			}
		}
	}

	if err = updGroup.Wait(); err != nil {
		return fmt.Errorf("failed to remove finalizer from certificate: %w", err)
	}
	return
}

func (h *CertificateHandler) UpdateCertificate(ctx context.Context, cert ManagedCertificate, spec *ManagedCertificateSpec) (err error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		if c, ok := cert.(*certManagerv1.Certificate); ok {
			updateResourceAnnotation(&c.ObjectMeta, spec.Hash())
			c.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", spec.OwnerGeneration)
			c.Spec = spec.getCertManagerCertificateSpec()
			_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
		} else {
			err = fmt.Errorf("failed to cast certificate to cert-manager type")
		}

	default:
		if c, ok := cert.(*certv1alpha1.Certificate); ok {
			updateResourceAnnotation(&c.ObjectMeta, spec.Hash())
			c.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", spec.OwnerGeneration)
			c.Spec = spec.getGardenerCertificateSpec()
			_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(c.Namespace).Update(ctx, c, metav1.UpdateOptions{})
		} else {
			err = fmt.Errorf("failed to cast certificate to gardener type")
		}
	}
	return
}

func (h *CertificateHandler) CreateCertificate(ctx context.Context, spec *ManagedCertificateSpec) (err error) {
	mo := metav1.ObjectMeta{
		Name:      spec.Name,
		Namespace: spec.Namespace,
		Labels: map[string]string{
			LabelOwnerIdentifierHash: sha1Sum(spec.OwnerId),
			LabelOwnerGeneration:     fmt.Sprintf("%d", spec.OwnerGeneration),
		},
		Annotations: map[string]string{
			AnnotationResourceHash:    spec.Hash(),
			AnnotationOwnerIdentifier: spec.OwnerId,
		},
		Finalizers: []string{FinalizerDomain},
	}
	switch h.managerType {
	case certManagerCertManagerIO:
		_, err = h.c.certManagerCertificateClient.CertmanagerV1().Certificates(spec.Namespace).Create(ctx, &certManagerv1.Certificate{
			ObjectMeta: mo,
			Spec:       spec.getCertManagerCertificateSpec(),
		}, metav1.CreateOptions{})

	default:
		_, err = h.c.gardenerCertificateClient.CertV1alpha1().Certificates(spec.Namespace).Create(ctx, &certv1alpha1.Certificate{
			ObjectMeta: mo,
			Spec:       spec.getGardenerCertificateSpec(),
		}, metav1.CreateOptions{})
	}
	return
}

func (h *CertificateHandler) IsCertificateReady(cert ManagedCertificate) (bool, error) {
	switch h.managerType {
	case certManagerCertManagerIO:
		if c, ok := cert.(*certManagerv1.Certificate); ok {
			readyCond := getCertManagerReadyCondition(c)
			// check for ready state
			if readyCond == nil || readyCond.Status == certManagermetav1.ConditionUnknown {
				return false, nil
			} else if readyCond.Status == certManagermetav1.ConditionFalse {
				return false, fmt.Errorf("%s not ready: %s", certManagerv1.CertificateKind, certv1alpha1.StateError, readyCond.Message)
			}
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

func getCertManagerReadyCondition(certificate *certManagerv1.Certificate) *certManagerv1.CertificateCondition {
	var readyCond *certManagerv1.CertificateCondition
	for _, cond := range certificate.Status.Conditions {
		if cond.Type == certManagerv1.CertificateConditionReady {
			readyCond = &cond
			break
		}
	}
	return readyCond
}

type ManagedCertificate interface {
	GetAnnotations() map[string]string
	GetName() string
	GetNamespace() string
	GetLabels() map[string]string
}

type ManagedCertificateSpec struct {
	Domain          string
	Name            string
	Namespace       string
	OwnerId         string
	OwnerGeneration int64
}

func (o *ManagedCertificateSpec) Hash() string {
	return sha256Sum(o.Domain, o.Name, o.Namespace)
}

func (o *ManagedCertificateSpec) getGardenerCertificateSpec() certv1alpha1.CertificateSpec {
	return certv1alpha1.CertificateSpec{
		DNSNames: []string{"*." + o.Domain},
		SecretRef: &corev1.SecretReference{
			Name:      o.Name,
			Namespace: o.Namespace,
		},
	}
}

func (o *ManagedCertificateSpec) getCertManagerCertificateSpec() certManagerv1.CertificateSpec {
	return certManagerv1.CertificateSpec{
		DNSNames:   []string{"*." + o.Domain},
		SecretName: o.Name,
		IssuerRef: certManagermetav1.ObjectReference{
			// TODO: make this configurable
			Kind: certManagerv1.ClusterIssuerKind,
			Name: "cluster-ca",
		},
	}
}
