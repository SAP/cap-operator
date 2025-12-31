/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"text/template"

	dnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	sprig "github.com/go-task/slim-sprig/v3"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
)

const (
	DomainEventSubdomainAlreadyInUse = "SubdomainAlreadyInUse"
	LabelDomainHostHash              = "sme.sap.com/domain-host-hash"
	subDomainTemplateVar             = ".subDomain"
)

var (
	cNameLookup = int64(30)
	ttl         = int64(600)
)

type dnsInfo struct {
	name   string
	target string
	appId  string
}

func handleDnsEntries[T v1alpha1.DomainEntity](ctx context.Context, c *Controller, dom T, ownerId, subResourceName string, subResourceNamespace string) (err error) {
	if dnsManager() != dnsManagerGardener {
		// skip dns entry handling if not using gardener dns manager
		return nil
	}

	list, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			LabelOwnerIdentifierHash: sha1Sum(ownerId),
		}).String(),
	})
	if err != nil {
		return fmt.Errorf("failed to list dns entries for %s: %w", ownerId, err)
	}

	overallDNSInfo, err := getDnsInfo(c, dom)
	if err != nil {
		return err
	}

	// check and update relevant existing dns entries
	aRelevantDNSNameHashes, relevantDNSInfo, err := checkRelevantDNSEntries(ctx, list.Items, overallDNSInfo, dom.GetMetadata().Generation, c)
	if err != nil {
		return err
	}

	// delete outdated dns entries
	// Add a requirement for OwnerIdentifierHash and SubdomainHash
	ownerReq, _ := labels.NewRequirement(LabelOwnerIdentifierHash, selection.Equals, []string{sha1Sum(ownerId)})
	// Create label selector based on the above requirement for filtering out all outdated dns entries
	deletionSelector := labels.NewSelector().Add(*ownerReq)
	if len(aRelevantDNSNameHashes) > 0 {
		// Add all known DNSName hash to new requirement
		dnsNameReq, _ := labels.NewRequirement(LabelDNSNameHash, selection.NotIn, aRelevantDNSNameHashes)
		deletionSelector = deletionSelector.Add(*dnsNameReq)
	}
	err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: deletionSelector.String()})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	// create new dns entries
	for _, info := range relevantDNSInfo {
		hash := sha256Sum(info.name, info.target, info.appId)
		dnsHash := sha1Sum(info.name)
		dnsEntry := &dnsv1alpha1.DNSEntry{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: subResourceName + "-",
				Namespace:    subResourceNamespace,
				Labels: map[string]string{
					LabelOwnerIdentifierHash:          sha1Sum(ownerId),
					LabelOwnerGeneration:              fmt.Sprintf("%d", dom.GetMetadata().Generation),
					LabelBTPApplicationIdentifierHash: info.appId,
					LabelDNSNameHash:                  dnsHash,
				},
				Annotations: map[string]string{
					AnnotationResourceHash:     hash,
					AnnotationOwnerIdentifier:  ownerId,
					GardenerDNSClassIdentifier: GardenerDNSClassValue,
				},
				// Finalizers: []string{FinalizerDomain},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(metav1.Object(dom), v1alpha1.SchemeGroupVersion.WithKind(dom.GetKind())),
				},
			},
			Spec: getDnsEntrySpec(info),
		}
		_, err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(subResourceNamespace).Create(ctx, dnsEntry, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create dns entry for %s: %w", info.name, err)
		}
	}

	return

}

func checkRelevantDNSEntries(ctx context.Context, dnsEntries []dnsv1alpha1.DNSEntry, overallDNSInfo []*dnsInfo, generation int64, c *Controller) (aRelevantDNSNameHashes []string, relevantDNSInfo []*dnsInfo, err error) {
	relevantDNSInfo = slices.Clone(overallDNSInfo)
	aRelevantDNSNameHashes = []string{}
	for _, entry := range dnsEntries {
		index := slices.IndexFunc(relevantDNSInfo, func(d *dnsInfo) bool {
			return d.name == entry.Spec.DNSName
		})
		if index >= 0 {
			info := relevantDNSInfo[index]
			dnsHash := sha1Sum(info.name)
			// update dns entry, if needed
			hash := sha256Sum(info.name, info.target, info.appId)
			if entry.Annotations[AnnotationResourceHash] != hash {
				updateResourceAnnotation(&entry.ObjectMeta, hash)
				entry.Labels[LabelOwnerGeneration] = fmt.Sprintf("%d", generation)
				entry.Labels[LabelBTPApplicationIdentifierHash] = info.appId
				entry.Labels[LabelDNSNameHash] = dnsHash
				entry.Spec = getDnsEntrySpec(info)
				_, err = c.gardenerDNSClient.DnsV1alpha1().DNSEntries(entry.Namespace).Update(ctx, &entry, metav1.UpdateOptions{})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to update dns entry %s.%s: %w", entry.Namespace, entry.Name, err)
				}
			}
			// remove the existing entry relevantDNSInfo to avoid creating a new entry, add to relevantDNSNameHashes
			relevantDNSInfo = slices.Delete(relevantDNSInfo, index, index+1)
			aRelevantDNSNameHashes = append(aRelevantDNSNameHashes, dnsHash)
		}
	}
	return aRelevantDNSNameHashes, relevantDNSInfo, nil
}

func getDnsEntrySpec(info *dnsInfo) dnsv1alpha1.DNSEntrySpec {
	return dnsv1alpha1.DNSEntrySpec{
		DNSName:             info.name,
		Targets:             []string{info.target},
		CNameLookupInterval: &cNameLookup,
		TTL:                 &ttl,
	}
}

func getDnsInfo[T v1alpha1.DomainEntity](c *Controller, dom T) (resolvedDNSInfo []*dnsInfo, err error) {
	dnsTemplates, subdomainInfo, err := getDNSDetails(dom, c)
	if err != nil {
		return nil, err
	}

	domVars := map[string]any{
		"domain":    dom.GetSpec().Domain,
		"dnsTarget": dom.GetStatus().DnsTarget,
	}
	// Setup template engine with sprig functions
	tpl := template.New("dnsTemplate").Funcs(sprig.FuncMap())

	resolvedDNSInfo = []*dnsInfo{}
	checkAndAppendDNSInfo := func(dnsInfo *dnsInfo) {
		if dnsInfo != nil {
			resolvedDNSInfo = append(resolvedDNSInfo, dnsInfo)
		}
	}

	for _, dnsTemplate := range dnsTemplates {
		var parsedDnsInfo *dnsInfo
		domVars["subDomain"] = ""
		if !strings.Contains(dnsTemplate.Name, subDomainTemplateVar) {
			parsedDnsInfo, err = parseDNSTemplate(tpl, dnsTemplate, domVars)
			if err != nil {
				return nil, err
			}
			checkAndAppendDNSInfo(parsedDnsInfo)
			continue
		}
		for subDomain, appId := range subdomainInfo {
			domVars["subDomain"] = subDomain
			parsedDnsInfo, err = parseDNSTemplate(tpl, dnsTemplate, domVars)
			if err != nil {
				return nil, err
			}
			parsedDnsInfo.appId = appId
			checkAndAppendDNSInfo(parsedDnsInfo)
		}
	}

	return resolvedDNSInfo, err
}

func getDNSDetails[T v1alpha1.DomainEntity](dom T, c *Controller) (dnsTemplates []v1alpha1.DNSTemplate, subdomainInfo map[string]string, err error) {
	dnsTemplates = []v1alpha1.DNSTemplate{}
	collectSubdomains := false

	switch dom.GetSpec().DNSMode {
	case v1alpha1.DnsModeWildcard:
		dnsTemplates = append(dnsTemplates, v1alpha1.DNSTemplate{Name: "*.{{.domain}}", Target: "{{.dnsTarget}}"})
	case v1alpha1.DnsModeSubdomain:
		dnsTemplates = append(dnsTemplates, v1alpha1.DNSTemplate{Name: "{{.subDomain}}.{{.domain}}", Target: "{{.dnsTarget}}"})
		// If subdomain is used, we need to collect subdomains from applications
		collectSubdomains = true
	case v1alpha1.DnsModeCustom:
		dnsTemplates = dom.GetSpec().DNSTemplates
		// If subdomain is used, we need to collect subdomains from applications
		collectSubdomains = slices.ContainsFunc(dnsTemplates, func(t v1alpha1.DNSTemplate) bool {
			return strings.Contains(t.Name, subDomainTemplateVar)
		})
	default: // Default is None
		//do nothing here
	}

	if collectSubdomains {
		subdomainInfo, err = collectAppSubdomainInfos(c, dom)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to collect subdomains from applications: %w", err)
		}
	}

	return dnsTemplates, subdomainInfo, nil
}

func parseDNSTemplate(tpl *template.Template, dnsTemplate v1alpha1.DNSTemplate, domVars map[string]any) (*dnsInfo, error) {
	// Parse the DNS templates
	parseTemplate := func(templateString string, templateVars map[string]any) (string, error) {
		var tmpS strings.Builder
		t := template.Must(tpl.Parse(templateString))
		err := t.Execute(&tmpS, templateVars)
		if err != nil {
			return "", fmt.Errorf("failed to parse template %s: %w", templateString, err)
		}
		return tmpS.String(), nil
	}
	var dns dnsInfo

	// Parse DNS name
	res, err := parseTemplate(dnsTemplate.Name, domVars)
	if err != nil {
		return nil, err
	}
	dns.name = res

	// Parse DNS target
	res, err = parseTemplate(dnsTemplate.Target, domVars)
	if err != nil {
		return nil, err
	}
	dns.target = res

	return &dns, nil
}

func collectAppSubdomainInfos[T v1alpha1.DomainEntity](c *Controller, dom T) (subdomains map[string]string, err error) {
	cas, err := getReferencingApplications(c, dom)
	if err != nil {
		return nil, err
	}

	subdomains = map[string]string{}

	for _, ca := range cas {
		if len(ca.Status.ObservedSubdomains) > 0 {
			for _, subdomain := range ca.Status.ObservedSubdomains {
				if appId, ok := subdomains[subdomain]; !ok {
					subdomains[subdomain] = ca.Labels[LabelBTPApplicationIdentifierHash]
				} else if appId != ca.Labels[LabelBTPApplicationIdentifierHash] {
					// this subdomain is already used by another application
					// skip and raise warning event
					c.Event(ca, runtime.Object(dom), corev1.EventTypeWarning, DomainEventSubdomainAlreadyInUse, EventActionProcessingDomainResources,
						fmt.Sprintf("Subdomain %s is already used by another application with domain %s (%s)", subdomain, formOwnerIdFromDomain(dom), dom.GetSpec().Domain))
				}
			}
		}
	}
	return subdomains, nil
}

func areDnsEntriesReady(ctx context.Context, c *Controller, ownerId string) (ready bool, err error) {
	if dnsManager() != dnsManagerGardener {
		// assume ready if not using gardener dns manager
		return true, nil
	}

	// create a label selector to filter dns entries by owner identifier hash
	selector := labels.SelectorFromSet(labels.Set{
		LabelOwnerIdentifierHash: sha1Sum(ownerId),
	})

	// list all dns entries which match the the domains (and subdomain, if supplied)
	dnsEntries, err := c.gardenerDNSClient.DnsV1alpha1().DNSEntries(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return false, fmt.Errorf("failed to list dns entries: %w", err)
	}

	// Check all matching dns entries
	for _, entry := range dnsEntries.Items {
		// check for ready state
		if entry.Status.State == dnsv1alpha1.StateError || entry.Status.State == dnsv1alpha1.StateInvalid {
			return false, fmt.Errorf("%s in state %s for %s: %s", dnsv1alpha1.DNSEntryKind, entry.Status.State, ownerId, *entry.Status.Message)
		} else if entry.Status.State != dnsv1alpha1.STATE_READY {
			return false, nil
		}
	}

	return true, nil
}
