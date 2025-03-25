/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/client/applyconfiguration/sme.sap.com/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeClusterDomains implements ClusterDomainInterface
type FakeClusterDomains struct {
	Fake *FakeSmeV1alpha1
	ns   string
}

var clusterdomainsResource = v1alpha1.SchemeGroupVersion.WithResource("clusterdomains")

var clusterdomainsKind = v1alpha1.SchemeGroupVersion.WithKind("ClusterDomain")

// Get takes name of the clusterDomain, and returns the corresponding clusterDomain object, and an error if there is any.
func (c *FakeClusterDomains) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ClusterDomain, err error) {
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(clusterdomainsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// List takes label and field selectors, and returns the list of ClusterDomains that match those selectors.
func (c *FakeClusterDomains) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ClusterDomainList, err error) {
	emptyResult := &v1alpha1.ClusterDomainList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(clusterdomainsResource, clusterdomainsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ClusterDomainList{ListMeta: obj.(*v1alpha1.ClusterDomainList).ListMeta}
	for _, item := range obj.(*v1alpha1.ClusterDomainList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested clusterDomains.
func (c *FakeClusterDomains) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(clusterdomainsResource, c.ns, opts))

}

// Create takes the representation of a clusterDomain and creates it.  Returns the server's representation of the clusterDomain, and an error, if there is any.
func (c *FakeClusterDomains) Create(ctx context.Context, clusterDomain *v1alpha1.ClusterDomain, opts v1.CreateOptions) (result *v1alpha1.ClusterDomain, err error) {
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(clusterdomainsResource, c.ns, clusterDomain, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// Update takes the representation of a clusterDomain and updates it. Returns the server's representation of the clusterDomain, and an error, if there is any.
func (c *FakeClusterDomains) Update(ctx context.Context, clusterDomain *v1alpha1.ClusterDomain, opts v1.UpdateOptions) (result *v1alpha1.ClusterDomain, err error) {
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(clusterdomainsResource, c.ns, clusterDomain, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeClusterDomains) UpdateStatus(ctx context.Context, clusterDomain *v1alpha1.ClusterDomain, opts v1.UpdateOptions) (result *v1alpha1.ClusterDomain, err error) {
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(clusterdomainsResource, "status", c.ns, clusterDomain, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// Delete takes name of the clusterDomain and deletes it. Returns an error if one occurs.
func (c *FakeClusterDomains) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(clusterdomainsResource, c.ns, name, opts), &v1alpha1.ClusterDomain{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeClusterDomains) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(clusterdomainsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ClusterDomainList{})
	return err
}

// Patch applies the patch and returns the patched clusterDomain.
func (c *FakeClusterDomains) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterDomain, err error) {
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(clusterdomainsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied clusterDomain.
func (c *FakeClusterDomains) Apply(ctx context.Context, clusterDomain *smesapcomv1alpha1.ClusterDomainApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterDomain, err error) {
	if clusterDomain == nil {
		return nil, fmt.Errorf("clusterDomain provided to Apply must not be nil")
	}
	data, err := json.Marshal(clusterDomain)
	if err != nil {
		return nil, err
	}
	name := clusterDomain.Name
	if name == nil {
		return nil, fmt.Errorf("clusterDomain.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(clusterdomainsResource, c.ns, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeClusterDomains) ApplyStatus(ctx context.Context, clusterDomain *smesapcomv1alpha1.ClusterDomainApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterDomain, err error) {
	if clusterDomain == nil {
		return nil, fmt.Errorf("clusterDomain provided to Apply must not be nil")
	}
	data, err := json.Marshal(clusterDomain)
	if err != nil {
		return nil, err
	}
	name := clusterDomain.Name
	if name == nil {
		return nil, fmt.Errorf("clusterDomain.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.ClusterDomain{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(clusterdomainsResource, c.ns, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.ClusterDomain), err
}
