/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"testing"
	"text/template"

	sprig "github.com/go-task/slim-sprig/v3"

	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestDomain(mode v1alpha2.DNSMode, templates []v1alpha2.DNSTemplate) *v1alpha2.Domain {
	return &v1alpha2.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "test-dom", Namespace: "default"},
		Spec: v1alpha2.DomainSpec{
			Domain:       "app-domain.test.local",
			DNSMode:      mode,
			DNSTemplates: templates,
		},
	}
}

func TestParseDNSTemplate_Errors(t *testing.T) {
	tpl := template.New("dnsTemplate").Funcs(sprig.FuncMap())
	domVars := map[string]any{"domain": "app-domain.test.local", "dnsTarget": "target.test.local", "subDomain": ""}

	// DNS name template fails to execute (field access on a string value)
	if _, err := parseDNSTemplate(tpl, v1alpha2.DNSTemplate{Name: "{{.domain.x}}", Target: "{{.dnsTarget}}"}, domVars); err == nil {
		t.Error("expected an error when the DNS name template fails to execute")
	}

	// DNS target template fails to execute (name is valid, target is not)
	if _, err := parseDNSTemplate(tpl, v1alpha2.DNSTemplate{Name: "{{.domain}}", Target: "{{.dnsTarget.x}}"}, domVars); err == nil {
		t.Error("expected an error when the DNS target template fails to execute")
	}
}

func TestGetDNSDetails_NoneMode(t *testing.T) {
	// DNSMode None -> no templates and no subdomain collection (controller not used)
	dnsTemplates, subdomainInfo, err := getDNSDetails(newTestDomain(v1alpha2.DnsModeNone, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dnsTemplates) != 0 {
		t.Errorf("expected no DNS templates for None mode, got: %v", dnsTemplates)
	}
	if subdomainInfo != nil {
		t.Errorf("expected no subdomain info for None mode, got: %v", subdomainInfo)
	}
}

func TestGetDnsInfo_TemplateError(t *testing.T) {
	// Custom mode with a template that fails to execute -> error surfaced from getDnsInfo
	dom := newTestDomain(v1alpha2.DnsModeCustom, []v1alpha2.DNSTemplate{{Name: "{{.domain.x}}", Target: "{{.dnsTarget}}"}})
	if _, err := getDnsInfo(nil, dom); err == nil {
		t.Error("expected an error when a custom DNS template fails to execute")
	}
}

func TestHandleDnsEntries_NonGardener(t *testing.T) {
	defer deregisterMetrics()
	t.Setenv(dnsManagerEnv, dnsManagerKubernetes)
	c := initializeControllerForReconciliationTests(t, nil, nil)

	// non-gardener dns manager -> handling is skipped without error
	if err := handleDnsEntries(context.TODO(), c, newTestDomain(v1alpha2.DnsModeWildcard, nil), "Domain.default.test-dom", "test-dom", "default"); err != nil {
		t.Errorf("expected no error for non-gardener dns manager, got: %v", err)
	}
}

func TestAreDnsEntriesReady_NonGardener(t *testing.T) {
	defer deregisterMetrics()
	t.Setenv(dnsManagerEnv, dnsManagerKubernetes)
	c := initializeControllerForReconciliationTests(t, nil, nil)

	// non-gardener dns manager -> assumed ready
	ready, err := areDnsEntriesReady(context.TODO(), c, "Domain.default.test-dom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ready {
		t.Error("expected dns entries to be assumed ready for non-gardener dns manager")
	}
}
