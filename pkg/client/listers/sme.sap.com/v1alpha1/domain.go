/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// DomainLister helps list Domains.
// All objects returned here must be treated as read-only.
type DomainLister interface {
	// List lists all Domains in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.Domain, err error)
	// Domains returns an object that can list and get Domains.
	Domains(namespace string) DomainNamespaceLister
	DomainListerExpansion
}

// domainLister implements the DomainLister interface.
type domainLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.Domain]
}

// NewDomainLister returns a new DomainLister.
func NewDomainLister(indexer cache.Indexer) DomainLister {
	return &domainLister{listers.New[*smesapcomv1alpha1.Domain](indexer, smesapcomv1alpha1.Resource("domain"))}
}

// Domains returns an object that can list and get Domains.
func (s *domainLister) Domains(namespace string) DomainNamespaceLister {
	return domainNamespaceLister{listers.NewNamespaced[*smesapcomv1alpha1.Domain](s.ResourceIndexer, namespace)}
}

// DomainNamespaceLister helps list and get Domains.
// All objects returned here must be treated as read-only.
type DomainNamespaceLister interface {
	// List lists all Domains in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.Domain, err error)
	// Get retrieves the Domain from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*smesapcomv1alpha1.Domain, error)
	DomainNamespaceListerExpansion
}

// domainNamespaceLister implements the DomainNamespaceLister
// interface.
type domainNamespaceLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.Domain]
}
