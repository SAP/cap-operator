/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
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

// CAPApplicationLister helps list CAPApplications.
// All objects returned here must be treated as read-only.
type CAPApplicationLister interface {
	// List lists all CAPApplications in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.CAPApplication, err error)
	// CAPApplications returns an object that can list and get CAPApplications.
	CAPApplications(namespace string) CAPApplicationNamespaceLister
	CAPApplicationListerExpansion
}

// cAPApplicationLister implements the CAPApplicationLister interface.
type cAPApplicationLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.CAPApplication]
}

// NewCAPApplicationLister returns a new CAPApplicationLister.
func NewCAPApplicationLister(indexer cache.Indexer) CAPApplicationLister {
	return &cAPApplicationLister{listers.New[*smesapcomv1alpha1.CAPApplication](indexer, smesapcomv1alpha1.Resource("capapplication"))}
}

// CAPApplications returns an object that can list and get CAPApplications.
func (s *cAPApplicationLister) CAPApplications(namespace string) CAPApplicationNamespaceLister {
	return cAPApplicationNamespaceLister{listers.NewNamespaced[*smesapcomv1alpha1.CAPApplication](s.ResourceIndexer, namespace)}
}

// CAPApplicationNamespaceLister helps list and get CAPApplications.
// All objects returned here must be treated as read-only.
type CAPApplicationNamespaceLister interface {
	// List lists all CAPApplications in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.CAPApplication, err error)
	// Get retrieves the CAPApplication from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*smesapcomv1alpha1.CAPApplication, error)
	CAPApplicationNamespaceListerExpansion
}

// cAPApplicationNamespaceLister implements the CAPApplicationNamespaceLister
// interface.
type cAPApplicationNamespaceLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.CAPApplication]
}
