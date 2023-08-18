// This file is needed just to show some coverage as go tests report coverage package wise. The usage in controller and server already cover most of the code.
/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"strings"
	"testing"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var serviceInfos = []v1alpha1.ServiceInfo{
	{
		Class:  "xsuaa",
		Name:   "test-xsuaa",
		Secret: "test-xsuaa-sec",
	},
	{
		Class:  "xsuaa",
		Name:   "test-xsuaa2",
		Secret: "test-xsuaa-sec2",
	},
	{
		Class:  "saas-registry",
		Name:   "test-saas",
		Secret: "test-saas-sec",
	},
	{
		Class:  "service-manager",
		Name:   "test-sm",
		Secret: "test-sm-sec",
	},
	{
		Class:  "destination",
		Name:   "test-dest",
		Secret: "test-dest-sec",
	},
	{
		Class:  "html5-apps-repo",
		Name:   "test-html-host",
		Secret: "test-html-host-sec",
	},
	{
		Class:  "html5-apps-repo",
		Name:   "test-html-rt",
		Secret: "test-html-rt-sec",
	},
}

func execTestsWithBLI(t *testing.T, name string, backlogItems []string, test func(t *testing.T)) {
	t.Run(name+", BLIs: "+strings.Join(backlogItems, ", "), test)
}

func TestGetXSUAAInfoMissingService(t *testing.T) {
	execTestsWithBLI(t, "Check that no uaa info is returned when no uaa service is present", []string{"ERP4SMEPREPWORKAPPPLAT-3773"}, func(t *testing.T) {
		res := GetXSUAAInfo([]v1alpha1.ServiceInfo{}, &v1alpha1.CAPApplication{})

		if res != nil {
			t.Error("unexpected uaa info")
		}
	})
}
func TestGetXSUAAInfoWithoutAnnotation(t *testing.T) {
	execTestsWithBLI(t, "Check that the 1st uaa info is returned with CA with no annotation is present", []string{"ERP4SMEPREPWORKAPPPLAT-3773"}, func(t *testing.T) {
		// CA without "sme.sap.com/primary-xsuaa" annotation
		ca := v1alpha1.CAPApplication{}

		res := GetXSUAAInfo(serviceInfos, &ca)

		if res.Name != "test-xsuaa" {
			t.Error("incorrect uaa info")
		}
	})
}

func TestGetXSUAAInfoWithAnnotation(t *testing.T) {
	execTestsWithBLI(t, "Check that the right uaa info is returned for CA with annotation present", []string{"ERP4SMEPREPWORKAPPPLAT-3773"}, func(t *testing.T) {
		// CA without "sme.sap.com/primary-xsuaa" annotation
		ca := v1alpha1.CAPApplication{
			ObjectMeta: v1.ObjectMeta{
				Annotations: map[string]string{
					AnnotationPrimaryXSUAA: "test-xsuaa2",
				},
			},
		}

		res := GetXSUAAInfo(serviceInfos, &ca)

		if res.Name != "test-xsuaa2" {
			t.Error("incorrect uaa info")
		}
	})
}
