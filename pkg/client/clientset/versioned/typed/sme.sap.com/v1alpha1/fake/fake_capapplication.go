/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
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

// FakeCAPApplications implements CAPApplicationInterface
type FakeCAPApplications struct {
	Fake *FakeSmeV1alpha1
	ns   string
}

var capapplicationsResource = v1alpha1.SchemeGroupVersion.WithResource("capapplications")

var capapplicationsKind = v1alpha1.SchemeGroupVersion.WithKind("CAPApplication")

// Get takes name of the cAPApplication, and returns the corresponding cAPApplication object, and an error if there is any.
func (c *FakeCAPApplications) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.CAPApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(capapplicationsResource, c.ns, name), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// List takes label and field selectors, and returns the list of CAPApplications that match those selectors.
func (c *FakeCAPApplications) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.CAPApplicationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(capapplicationsResource, capapplicationsKind, c.ns, opts), &v1alpha1.CAPApplicationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.CAPApplicationList{ListMeta: obj.(*v1alpha1.CAPApplicationList).ListMeta}
	for _, item := range obj.(*v1alpha1.CAPApplicationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cAPApplications.
func (c *FakeCAPApplications) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(capapplicationsResource, c.ns, opts))

}

// Create takes the representation of a cAPApplication and creates it.  Returns the server's representation of the cAPApplication, and an error, if there is any.
func (c *FakeCAPApplications) Create(ctx context.Context, cAPApplication *v1alpha1.CAPApplication, opts v1.CreateOptions) (result *v1alpha1.CAPApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(capapplicationsResource, c.ns, cAPApplication), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// Update takes the representation of a cAPApplication and updates it. Returns the server's representation of the cAPApplication, and an error, if there is any.
func (c *FakeCAPApplications) Update(ctx context.Context, cAPApplication *v1alpha1.CAPApplication, opts v1.UpdateOptions) (result *v1alpha1.CAPApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(capapplicationsResource, c.ns, cAPApplication), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCAPApplications) UpdateStatus(ctx context.Context, cAPApplication *v1alpha1.CAPApplication, opts v1.UpdateOptions) (*v1alpha1.CAPApplication, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(capapplicationsResource, "status", c.ns, cAPApplication), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// Delete takes name of the cAPApplication and deletes it. Returns an error if one occurs.
func (c *FakeCAPApplications) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(capapplicationsResource, c.ns, name, opts), &v1alpha1.CAPApplication{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCAPApplications) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(capapplicationsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.CAPApplicationList{})
	return err
}

// Patch applies the patch and returns the patched cAPApplication.
func (c *FakeCAPApplications) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(capapplicationsResource, c.ns, name, pt, data, subresources...), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied cAPApplication.
func (c *FakeCAPApplications) Apply(ctx context.Context, cAPApplication *smesapcomv1alpha1.CAPApplicationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplication, err error) {
	if cAPApplication == nil {
		return nil, fmt.Errorf("cAPApplication provided to Apply must not be nil")
	}
	data, err := json.Marshal(cAPApplication)
	if err != nil {
		return nil, err
	}
	name := cAPApplication.Name
	if name == nil {
		return nil, fmt.Errorf("cAPApplication.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(capapplicationsResource, c.ns, *name, types.ApplyPatchType, data), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeCAPApplications) ApplyStatus(ctx context.Context, cAPApplication *smesapcomv1alpha1.CAPApplicationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplication, err error) {
	if cAPApplication == nil {
		return nil, fmt.Errorf("cAPApplication provided to Apply must not be nil")
	}
	data, err := json.Marshal(cAPApplication)
	if err != nil {
		return nil, err
	}
	name := cAPApplication.Name
	if name == nil {
		return nil, fmt.Errorf("cAPApplication.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(capapplicationsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1alpha1.CAPApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CAPApplication), err
}
