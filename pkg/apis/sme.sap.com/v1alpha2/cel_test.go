/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha2_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

// These tests exercise the schema validations generated into the CRDs using the exact
// validators the kube-apiserver uses. They load the generated CRD YAML, so they also guard
// that the Go markers actually produce the expected rules.
//
// Two validators are used:
//   - CEL (x-kubernetes-validations) via cel.Validator - immutability / transition rules.
//   - OpenAPI structural schema via validation.ValidateCustomResource - required, MinLength, etc.
//
// Note: the fake clientset used by the webhook tests does NOT evaluate either of these (no
// apiserver), which is why these rules need a dedicated harness.

const storageVersion = "v1alpha2"

// loadInternalSchema loads the given CRD version's schema and converts it to the internal
// representation shared by the CEL and OpenAPI validators.
func loadInternalSchema(t *testing.T, crdFile, version string) *apiextensions.JSONSchemaProps {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "crds", crdFile))
	if err != nil {
		t.Fatalf("reading CRD %s: %v", crdFile, err)
	}

	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, crd); err != nil {
		t.Fatalf("unmarshalling CRD %s: %v", crdFile, err)
	}

	var v1Schema *apiextensionsv1.JSONSchemaProps
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Name == version {
			v1Schema = crd.Spec.Versions[i].Schema.OpenAPIV3Schema
			break
		}
	}
	if v1Schema == nil {
		t.Fatalf("version %s not found in CRD %s", version, crdFile)
	}

	internal := &apiextensions.JSONSchemaProps{}
	if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(v1Schema, internal, nil); err != nil {
		t.Fatalf("converting schema for %s: %v", crdFile, err)
	}
	return internal
}

// celValidatorForCRD returns a CEL validator for the given CRD version's x-kubernetes-validations.
func celValidatorForCRD(t *testing.T, crdFile, version string) (*cel.Validator, *structuralschema.Structural) {
	t.Helper()

	internal := loadInternalSchema(t, crdFile, version)
	structural, err := structuralschema.NewStructural(internal)
	if err != nil {
		t.Fatalf("building structural schema for %s: %v", crdFile, err)
	}

	validator := cel.NewValidator(structural, true, celconfig.PerCallLimit)
	if validator == nil {
		t.Fatalf("CRD %s version %s has no x-kubernetes-validations rules", crdFile, version)
	}
	return validator, structural
}

// openAPIValidatorForCRD returns an OpenAPI structural-schema validator (required, MinLength, etc.).
func openAPIValidatorForCRD(t *testing.T, crdFile, version string) validation.SchemaValidator {
	t.Helper()

	internal := loadInternalSchema(t, crdFile, version)
	validator, _, err := validation.NewSchemaValidator(internal)
	if err != nil {
		t.Fatalf("building OpenAPI validator for %s: %v", crdFile, err)
	}
	return validator
}

// expectOpenAPIValid asserts the object passes OpenAPI schema validation.
func expectOpenAPIValid(t *testing.T, validator validation.SchemaValidator, obj map[string]interface{}) {
	t.Helper()
	if errs := validation.ValidateCustomResource(field.NewPath("root"), obj, validator); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}

// expectOpenAPIFieldError asserts OpenAPI schema validation reports an error on a field whose
// path contains fieldSubstr.
func expectOpenAPIFieldError(t *testing.T, validator validation.SchemaValidator, obj map[string]interface{}, fieldSubstr string) {
	t.Helper()
	errs := validation.ValidateCustomResource(field.NewPath("root"), obj, validator)
	for _, e := range errs {
		if strings.Contains(e.Field, fieldSubstr) {
			return
		}
	}
	t.Fatalf("expected a validation error on a field containing %q, got %v", fieldSubstr, errs)
}

// expectValid runs the CEL rules and asserts whether obj (transitioning from oldObj) is accepted.
// oldObj is nil for a Create (transition rules referencing oldSelf are skipped).
func expectValid(t *testing.T, validator *cel.Validator, structural *structuralschema.Structural, obj, oldObj map[string]interface{}, wantAllowed bool) {
	t.Helper()

	var old interface{}
	if oldObj != nil {
		old = oldObj
	}
	errs, _ := validator.Validate(context.Background(), field.NewPath("root"), structural, obj, old, celconfig.RuntimeCELCostBudget)

	allowed := len(errs) == 0
	if allowed != wantAllowed {
		t.Fatalf("expected allowed=%v, got allowed=%v (errors: %v)", wantAllowed, allowed, errs)
	}
}

func TestCELCAPApplicationProviderImmutability(t *testing.T) {
	validator, structural := celValidatorForCRD(t, "sme.sap.com_capapplications.yaml", storageVersion)

	withProvider := func(sub, tenant string) map[string]interface{} {
		return map[string]interface{}{
			"spec": map[string]interface{}{
				"providerSubaccountId": "sub-1",
				"btpAppName":           "app-1",
				"provider": map[string]interface{}{
					"subDomain": sub,
					"tenantId":  tenant,
				},
			},
		}
	}
	withoutProvider := func() map[string]interface{} {
		return map[string]interface{}{
			"spec": map[string]interface{}{
				"providerSubaccountId": "sub-1",
				"btpAppName":           "app-1",
			},
		}
	}

	tests := []struct {
		name        string
		obj         map[string]interface{}
		oldObj      map[string]interface{}
		wantAllowed bool
	}{
		{name: "create with provider is allowed", obj: withProvider("sd", "t1"), oldObj: nil, wantAllowed: true},
		{name: "unchanged provider is allowed", obj: withProvider("sd", "t1"), oldObj: withProvider("sd", "t1"), wantAllowed: true},
		{name: "changing provider is rejected", obj: withProvider("sd", "t2"), oldObj: withProvider("sd", "t1"), wantAllowed: false},
		{name: "removing provider is allowed", obj: withoutProvider(), oldObj: withProvider("sd", "t1"), wantAllowed: true},
		{name: "adding provider is rejected", obj: withProvider("sd", "t1"), oldObj: withoutProvider(), wantAllowed: false},
		{name: "no provider on either side is allowed", obj: withoutProvider(), oldObj: withoutProvider(), wantAllowed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectValid(t, validator, structural, test.obj, test.oldObj, test.wantAllowed)
		})
	}
}

func TestCELCAPApplicationVersionSpecImmutability(t *testing.T) {
	validator, structural := celValidatorForCRD(t, "sme.sap.com_capapplicationversions.yaml", storageVersion)

	spec := func(version string) map[string]interface{} {
		return map[string]interface{}{
			"spec": map[string]interface{}{
				"capApplicationInstance": "ca-1",
				"version":                version,
				"workloads": []interface{}{
					map[string]interface{}{
						"name":                "cap-backend",
						"consumedBTPServices": []interface{}{},
						"deploymentDefinition": map[string]interface{}{
							"type": "CAP",
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name        string
		obj         map[string]interface{}
		oldObj      map[string]interface{}
		wantAllowed bool
	}{
		{name: "create is allowed", obj: spec("1.0.0"), oldObj: nil, wantAllowed: true},
		{name: "unchanged spec is allowed", obj: spec("1.0.0"), oldObj: spec("1.0.0"), wantAllowed: true},
		{name: "changing spec is rejected", obj: spec("1.0.1"), oldObj: spec("1.0.0"), wantAllowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectValid(t, validator, structural, test.obj, test.oldObj, test.wantAllowed)
		})
	}
}

func TestCELCAPTenantCapApplicationInstanceImmutability(t *testing.T) {
	validator, structural := celValidatorForCRD(t, "sme.sap.com_captenants.yaml", storageVersion)

	spec := func(instance string) map[string]interface{} {
		return map[string]interface{}{
			"spec": map[string]interface{}{
				"capApplicationInstance": instance,
				"subDomain":              "sd",
				"tenantId":               "t1",
			},
		}
	}

	tests := []struct {
		name        string
		obj         map[string]interface{}
		oldObj      map[string]interface{}
		wantAllowed bool
	}{
		{name: "create is allowed", obj: spec("ca-1"), oldObj: nil, wantAllowed: true},
		{name: "unchanged capApplicationInstance is allowed", obj: spec("ca-1"), oldObj: spec("ca-1"), wantAllowed: true},
		{name: "changing capApplicationInstance is rejected", obj: spec("ca-2"), oldObj: spec("ca-1"), wantAllowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectValid(t, validator, structural, test.obj, test.oldObj, test.wantAllowed)
		})
	}
}

// TestCELCAPApplicationIdentifierImmutability covers the +k8s:immutable markers on
// providerSubaccountId and btpAppName (generated as field-level `self == oldSelf` CEL rules).
func TestCELCAPApplicationIdentifierImmutability(t *testing.T) {
	validator, structural := celValidatorForCRD(t, "sme.sap.com_capapplications.yaml", storageVersion)

	spec := func(sub, app string) map[string]interface{} {
		return map[string]interface{}{
			"spec": map[string]interface{}{
				"providerSubaccountId": sub,
				"btpAppName":           app,
			},
		}
	}

	tests := []struct {
		name        string
		obj         map[string]interface{}
		oldObj      map[string]interface{}
		wantAllowed bool
	}{
		{name: "create is allowed", obj: spec("sub-1", "app-1"), oldObj: nil, wantAllowed: true},
		{name: "unchanged identifiers are allowed", obj: spec("sub-1", "app-1"), oldObj: spec("sub-1", "app-1"), wantAllowed: true},
		{name: "changing providerSubaccountId is rejected", obj: spec("sub-2", "app-1"), oldObj: spec("sub-1", "app-1"), wantAllowed: false},
		{name: "changing btpAppName is rejected", obj: spec("sub-1", "app-2"), oldObj: spec("sub-1", "app-1"), wantAllowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectValid(t, validator, structural, test.obj, test.oldObj, test.wantAllowed)
		})
	}
}

// TestOpenAPICAPApplicationRequiredIdentifiers covers that providerSubaccountId and btpAppName
// are required and non-empty (required + MinLength=1), enforced by the OpenAPI structural schema.
func TestOpenAPICAPApplicationRequiredIdentifiers(t *testing.T) {
	validator := openAPIValidatorForCRD(t, "sme.sap.com_capapplications.yaml", storageVersion)

	// base is a minimal spec satisfying all required fields (providerSubaccountId, btpAppName, btp).
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"metadata": map[string]interface{}{"name": "test-ca"},
			"spec": map[string]interface{}{
				"providerSubaccountId": "sub-1",
				"btpAppName":           "app-1",
				"btp":                  map[string]interface{}{"services": []interface{}{}},
			},
		}
	}
	specOf := func(obj map[string]interface{}) map[string]interface{} {
		return obj["spec"].(map[string]interface{})
	}

	t.Run("valid when both identifiers are set", func(t *testing.T) {
		expectOpenAPIValid(t, validator, base())
	})
	t.Run("missing providerSubaccountId is rejected", func(t *testing.T) {
		obj := base()
		delete(specOf(obj), "providerSubaccountId")
		expectOpenAPIFieldError(t, validator, obj, "providerSubaccountId")
	})
	t.Run("empty providerSubaccountId is rejected", func(t *testing.T) {
		obj := base()
		specOf(obj)["providerSubaccountId"] = ""
		expectOpenAPIFieldError(t, validator, obj, "providerSubaccountId")
	})
	t.Run("missing btpAppName is rejected", func(t *testing.T) {
		obj := base()
		delete(specOf(obj), "btpAppName")
		expectOpenAPIFieldError(t, validator, obj, "btpAppName")
	})
	t.Run("empty btpAppName is rejected", func(t *testing.T) {
		obj := base()
		specOf(obj)["btpAppName"] = ""
		expectOpenAPIFieldError(t, validator, obj, "btpAppName")
	})
}
