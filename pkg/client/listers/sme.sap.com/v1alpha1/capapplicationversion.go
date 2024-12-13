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

// CAPApplicationVersionLister helps list CAPApplicationVersions.
// All objects returned here must be treated as read-only.
type CAPApplicationVersionLister interface {
	// List lists all CAPApplicationVersions in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.CAPApplicationVersion, err error)
	// CAPApplicationVersions returns an object that can list and get CAPApplicationVersions.
	CAPApplicationVersions(namespace string) CAPApplicationVersionNamespaceLister
	CAPApplicationVersionListerExpansion
}

// cAPApplicationVersionLister implements the CAPApplicationVersionLister interface.
type cAPApplicationVersionLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.CAPApplicationVersion]
}

// NewCAPApplicationVersionLister returns a new CAPApplicationVersionLister.
func NewCAPApplicationVersionLister(indexer cache.Indexer) CAPApplicationVersionLister {
	return &cAPApplicationVersionLister{listers.New[*smesapcomv1alpha1.CAPApplicationVersion](indexer, smesapcomv1alpha1.Resource("capapplicationversion"))}
}

// CAPApplicationVersions returns an object that can list and get CAPApplicationVersions.
func (s *cAPApplicationVersionLister) CAPApplicationVersions(namespace string) CAPApplicationVersionNamespaceLister {
	return cAPApplicationVersionNamespaceLister{listers.NewNamespaced[*smesapcomv1alpha1.CAPApplicationVersion](s.ResourceIndexer, namespace)}
}

// CAPApplicationVersionNamespaceLister helps list and get CAPApplicationVersions.
// All objects returned here must be treated as read-only.
type CAPApplicationVersionNamespaceLister interface {
	// List lists all CAPApplicationVersions in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*smesapcomv1alpha1.CAPApplicationVersion, err error)
	// Get retrieves the CAPApplicationVersion from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*smesapcomv1alpha1.CAPApplicationVersion, error)
	CAPApplicationVersionNamespaceListerExpansion
}

// cAPApplicationVersionNamespaceLister implements the CAPApplicationVersionNamespaceLister
// interface.
type cAPApplicationVersionNamespaceLister struct {
	listers.ResourceIndexer[*smesapcomv1alpha1.CAPApplicationVersion]
}
