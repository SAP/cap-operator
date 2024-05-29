/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1alpha1 "github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	smesapcomv1alpha1 "github.com/sap/cap-operator/pkg/client/applyconfiguration/sme.sap.com/v1alpha1"
	scheme "github.com/sap/cap-operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CAPTenantOperationsGetter has a method to return a CAPTenantOperationInterface.
// A group's client should implement this interface.
type CAPTenantOperationsGetter interface {
	CAPTenantOperations(namespace string) CAPTenantOperationInterface
}

// CAPTenantOperationInterface has methods to work with CAPTenantOperation resources.
type CAPTenantOperationInterface interface {
	Create(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.CreateOptions) (*v1alpha1.CAPTenantOperation, error)
	Update(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (*v1alpha1.CAPTenantOperation, error)
	UpdateStatus(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (*v1alpha1.CAPTenantOperation, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.CAPTenantOperation, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.CAPTenantOperationList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPTenantOperation, err error)
	Apply(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error)
	ApplyStatus(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error)
	CAPTenantOperationExpansion
}

// cAPTenantOperations implements CAPTenantOperationInterface
type cAPTenantOperations struct {
	client rest.Interface
	ns     string
}

// newCAPTenantOperations returns a CAPTenantOperations
func newCAPTenantOperations(c *SmeV1alpha1Client, namespace string) *cAPTenantOperations {
	return &cAPTenantOperations{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the cAPTenantOperation, and returns the corresponding cAPTenantOperation object, and an error if there is any.
func (c *cAPTenantOperations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CAPTenantOperations that match those selectors.
func (c *cAPTenantOperations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.CAPTenantOperationList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.CAPTenantOperationList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("captenantoperations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested cAPTenantOperations.
func (c *cAPTenantOperations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("captenantoperations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a cAPTenantOperation and creates it.  Returns the server's representation of the cAPTenantOperation, and an error, if there is any.
func (c *cAPTenantOperations) Create(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.CreateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("captenantoperations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPTenantOperation).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a cAPTenantOperation and updates it. Returns the server's representation of the cAPTenantOperation, and an error, if there is any.
func (c *cAPTenantOperations) Update(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(cAPTenantOperation.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPTenantOperation).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *cAPTenantOperations) UpdateStatus(ctx context.Context, cAPTenantOperation *v1alpha1.CAPTenantOperation, opts v1.UpdateOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(cAPTenantOperation.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPTenantOperation).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the cAPTenantOperation and deletes it. Returns an error if one occurs.
func (c *cAPTenantOperations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *cAPTenantOperations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("captenantoperations").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched cAPTenantOperation.
func (c *cAPTenantOperations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPTenantOperation, err error) {
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied cAPTenantOperation.
func (c *cAPTenantOperations) Apply(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	if cAPTenantOperation == nil {
		return nil, fmt.Errorf("cAPTenantOperation provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(cAPTenantOperation)
	if err != nil {
		return nil, err
	}
	name := cAPTenantOperation.Name
	if name == nil {
		return nil, fmt.Errorf("cAPTenantOperation.Name must be provided to Apply")
	}
	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *cAPTenantOperations) ApplyStatus(ctx context.Context, cAPTenantOperation *smesapcomv1alpha1.CAPTenantOperationApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPTenantOperation, err error) {
	if cAPTenantOperation == nil {
		return nil, fmt.Errorf("cAPTenantOperation provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(cAPTenantOperation)
	if err != nil {
		return nil, err
	}

	name := cAPTenantOperation.Name
	if name == nil {
		return nil, fmt.Errorf("cAPTenantOperation.Name must be provided to Apply")
	}

	result = &v1alpha1.CAPTenantOperation{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("captenantoperations").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
