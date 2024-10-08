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

// FakeCAPTenantOperations implements CAPTenantOperationInterface
type FakeCAPTenantOperations struct {
	Fake *FakeSmeV1alpha1
	ns   string
}

var captenantoperationsResource = v1alpha1.SchemeGroupVersion.WithResource("captenantoperations")

var captenantoperationsKind = v1alpha1.SchemeGroupVersion.WithKind("CAPTenantOperation")

// Get takes name of the cAPTenantOperation, and returns the corresponding cAPTenantOperation object, and an error if there is any.
func (c *FakeCAPTenantOperations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(captenantoperationsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// List takes label and field selectors, and returns the list of CAPTenantOperations that match those selectors.
func (c *FakeCAPTenantOperations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.CAPTenantOperationList, err error) {
	emptyResult := &v1alpha1.CAPTenantOperationList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(captenantoperationsResource, captenantoperationsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.CAPTenantOperationList{ListMeta: obj.(*v1alpha1.CAPTenantOperationList).ListMeta}
	for _, item := range obj.(*v1alpha1.CAPTenantOperationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cAPTenantOperations.
func (c *FakeCAPTenantOperations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(captenantoperationsResource, c.ns, opts))

}

// Create takes the representation of a cAPTenantOperation and creates it.  Returns the server's representation of the cAPTenantOperation, and an error, if there is any.
func (c *FakeCAPTenantOperations) Create(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.CreateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(captenantoperationsResource, c.ns, cAPTenantOperation, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// Update takes the representation of a cAPTenantOperation and updates it. Returns the server's representation of the cAPTenantOperation, and an error, if there is any.
func (c *FakeCAPTenantOperations) Update(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(captenantoperationsResource, c.ns, cAPTenantOperation, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCAPTenantOperations) UpdateStatus(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(captenantoperationsResource, "status", c.ns, cAPTenantOperation, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// Delete takes name of the cAPTenantOperation and deletes it. Returns an error if one occurs.
func (c *FakeCAPTenantOperations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(captenantoperationsResource, c.ns, name, opts), &v1alpha1.CAPTenantOperation{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCAPTenantOperations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(captenantoperationsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.CAPTenantOperationList{})
	return err
}

// Patch applies the patch and returns the patched cAPTenantOperation.
func (c *FakeCAPTenantOperations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPTenantOperation, err error) {
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(captenantoperationsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied cAPTenantOperation.
func (c *FakeCAPTenantOperations) Apply(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	if cAPTenantOperation == nil {
		return nil, fmt.Errorf("cAPTenantOperation provided to Apply must not be nil")
	}
	data, err := json.Marshal(cAPTenantOperation)
	if err != nil {
		return nil, err
	}
	name := cAPTenantOperation.Name
	if name == nil {
		return nil, fmt.Errorf("cAPTenantOperation.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(captenantoperationsResource, c.ns, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeCAPTenantOperations) ApplyStatus(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	if cAPTenantOperation == nil {
		return nil, fmt.Errorf("cAPTenantOperation provided to Apply must not be nil")
	}
	data, err := json.Marshal(cAPTenantOperation)
	if err != nil {
		return nil, err
	}
	name := cAPTenantOperation.Name
	if name == nil {
		return nil, fmt.Errorf("cAPTenantOperation.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.CAPTenantOperation{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(captenantoperationsResource, c.ns, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.CAPTenantOperation), err
}
