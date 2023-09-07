/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
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

// CAPApplicationVersionsGetter has a method to return a CAPApplicationVersionInterface.
// A group's client should implement this interface.
type CAPApplicationVersionsGetter interface {
	CAPApplicationVersions(namespace string) CAPApplicationVersionInterface
}

// CAPApplicationVersionInterface has methods to work with CAPApplicationVersion resources.
type CAPApplicationVersionInterface interface {
	Create(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.CreateOptions) (*v1alpha1.CAPApplicationVersion, error)
	Update(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.UpdateOptions) (*v1alpha1.CAPApplicationVersion, error)
	UpdateStatus(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.UpdateOptions) (*v1alpha1.CAPApplicationVersion, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.CAPApplicationVersion, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.CAPApplicationVersionList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPApplicationVersion, err error)
	Apply(ctx context.Context, cAPApplicationVersion *smesapcomv1alpha1.CAPApplicationVersionApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplicationVersion, err error)
	ApplyStatus(ctx context.Context, cAPApplicationVersion *smesapcomv1alpha1.CAPApplicationVersionApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplicationVersion, err error)
	CAPApplicationVersionExpansion
}

// cAPApplicationVersions implements CAPApplicationVersionInterface
type cAPApplicationVersions struct {
	client rest.Interface
	ns     string
}

// newCAPApplicationVersions returns a CAPApplicationVersions
func newCAPApplicationVersions(c *SmeV1alpha1Client, namespace string) *cAPApplicationVersions {
	return &cAPApplicationVersions{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the cAPApplicationVersion, and returns the corresponding cAPApplicationVersion object, and an error if there is any.
func (c *cAPApplicationVersions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CAPApplicationVersions that match those selectors.
func (c *cAPApplicationVersions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.CAPApplicationVersionList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.CAPApplicationVersionList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("capapplicationversions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested cAPApplicationVersions.
func (c *cAPApplicationVersions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("capapplicationversions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a cAPApplicationVersion and creates it.  Returns the server's representation of the cAPApplicationVersion, and an error, if there is any.
func (c *cAPApplicationVersions) Create(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.CreateOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("capapplicationversions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPApplicationVersion).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a cAPApplicationVersion and updates it. Returns the server's representation of the cAPApplicationVersion, and an error, if there is any.
func (c *cAPApplicationVersions) Update(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.UpdateOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(cAPApplicationVersion.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPApplicationVersion).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *cAPApplicationVersions) UpdateStatus(ctx context.Context, cAPApplicationVersion *v1alpha1.CAPApplicationVersion, opts v1.UpdateOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(cAPApplicationVersion.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cAPApplicationVersion).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the cAPApplicationVersion and deletes it. Returns an error if one occurs.
func (c *cAPApplicationVersions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *cAPApplicationVersions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("capapplicationversions").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched cAPApplicationVersion.
func (c *cAPApplicationVersions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CAPApplicationVersion, err error) {
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied cAPApplicationVersion.
func (c *cAPApplicationVersions) Apply(ctx context.Context, cAPApplicationVersion *smesapcomv1alpha1.CAPApplicationVersionApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	if cAPApplicationVersion == nil {
		return nil, fmt.Errorf("cAPApplicationVersion provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(cAPApplicationVersion)
	if err != nil {
		return nil, err
	}
	name := cAPApplicationVersion.Name
	if name == nil {
		return nil, fmt.Errorf("cAPApplicationVersion.Name must be provided to Apply")
	}
	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *cAPApplicationVersions) ApplyStatus(ctx context.Context, cAPApplicationVersion *smesapcomv1alpha1.CAPApplicationVersionApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.CAPApplicationVersion, err error) {
	if cAPApplicationVersion == nil {
		return nil, fmt.Errorf("cAPApplicationVersion provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(cAPApplicationVersion)
	if err != nil {
		return nil, err
	}

	name := cAPApplicationVersion.Name
	if name == nil {
		return nil, fmt.Errorf("cAPApplicationVersion.Name must be provided to Apply")
	}

	result = &v1alpha1.CAPApplicationVersion{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("capapplicationversions").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
