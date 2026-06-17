/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"
)

const (
	LabelTenantType                      = "sme.sap.com/tenant-type"
	LabelTenantId                        = "sme.sap.com/btp-tenant-id"
	ProviderTenantType                   = "provider"
	AdmissionError                       = "admission error:"
	InvalidResource                      = "invalid resource"
	InvalidationMessage                  = "invalidated from webhook"
	ValidationMessage                    = "validated from webhook"
	RequestPath                          = "/request"
	DeploymentWorkloadCountErr           = "%s %s there should always be one workload deployment definition of type %s. Currently, there are %d workloads of type %s"
	TenantOpMissingErr                   = "%s %s there should always be one job workload of type TenantOperation. Currently, there are none."
	TenantOpJobWorkloadCountErr          = "%s %s there should not be any job workload of type %s or %s defined for service only applications."
	ServiceExposureWorkloadNameErr       = "%s %s workload name %s mentioned as part of routes in service exposure with subDomain %s is not a valid workload."
	ServiceExposurePortErr               = "%s %s port %d mentioned as part of routes for workload %s in service exposure with subDomain %s is not a valid port in the workload."
	DuplicateServiceExposureSubDomainErr = "%s %s duplicate subDomain %s in service exposure"
	DomainsDeprecated                    = "%s %s domains are deprecated. Use domainRefs instead in: %s.%s"
)

const (
	defaultServerPort = 4004
	defaultRouterPort = 5000
)

type validateResource struct {
	errorOccured bool
	allowed      bool
	message      string
}

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
	workloadNameRegex     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

type WebhookHandler struct {
	CrdClient versioned.Interface
}

func checkWorkloadPort(workload *v1alpha1.WorkloadDetails) validateResource {
	if workload.DeploymentDefinition == nil {
		return validAdmissionReviewObj()
	}

	if len(workload.DeploymentDefinition.Ports) == 0 {
		return validAdmissionReviewObj()
	}

	seenPortNames := make(map[string]struct{})
	seenPortNums := make(map[int32]struct{})
	routerDestinationNameFound := false
	for _, port := range workload.DeploymentDefinition.Ports {
		if port.RouterDestinationName != "" {
			routerDestinationNameFound = true
		}
		if _, dup := seenPortNames[port.Name]; dup {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate port name: %s in workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, port.Name, workload.Name),
			}
		}
		seenPortNames[port.Name] = struct{}{}
		if _, dup := seenPortNums[port.Port]; dup {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate port number: %d in workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, port.Port, workload.Name),
			}
		}
		seenPortNums[port.Port] = struct{}{}
	}

	if !routerDestinationNameFound && workload.DeploymentDefinition.Type == v1alpha1.DeploymentCAP { // workloads of type Additional need not have a router destination
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s routerDestinationName not defined in port configuration of workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workload.Name),
		}
	}

	if routerDestinationNameFound && workload.DeploymentDefinition.Type == v1alpha1.DeploymentRouter {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s routerDestinationName should not be defined for workload of type Router - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workload.Name),
		}
	}

	return validAdmissionReviewObj()
}

var (
	validDeploymentTypes = []v1alpha1.DeploymentType{v1alpha1.DeploymentCAP, v1alpha1.DeploymentRouter, v1alpha1.DeploymentAdditional, v1alpha1.DeploymentService}
	validJobTypes        = []v1alpha1.JobType{v1alpha1.JobContent, v1alpha1.JobTenantOperation, v1alpha1.JobCustomTenantOperation}
)

func checkWorkloadType(workload *v1alpha1.WorkloadDetails) validateResource {
	if workload.DeploymentDefinition != nil && !slices.Contains(validDeploymentTypes, workload.DeploymentDefinition.Type) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s invalid deployment definition type. Only supported - CAP, Router, Additional and Service", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	if workload.JobDefinition != nil && !slices.Contains(validJobTypes, workload.JobDefinition.Type) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s invalid job definition type. Only supported - Content, TenantOperation and CustomTenantOperation", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	return validAdmissionReviewObj()
}

func checkDerivedNameLength(cavName, workloadName, suffix, noun string) validateResource {
	const maxNameLength = 63
	derived := cavName + "-" + workloadName + "-" + suffix
	if len(derived) > maxNameLength {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf(
				"%s %s Derived %s '%s' (length %d) exceeds max limit of %d characters. Please shorten CAPApplicationVersion name '%s' or workload name '%s'.",
				InvalidationMessage, v1alpha1.CAPApplicationVersionKind,
				noun, derived, len(derived), maxNameLength, cavName, workloadName,
			),
		}
	}
	return validAdmissionReviewObj()
}

func checkWorkloadNameLength(cavObjNew *v1alpha1.CAPApplicationVersion, workload *v1alpha1.WorkloadDetails) validateResource {
	if workload.DeploymentDefinition != nil {
		if v := checkDerivedNameLength(cavObjNew.Name, workload.Name, "svc", "service name"); !v.allowed {
			return v
		}
	}

	// Content job length should not exceed 63 characters considering the generated pod name (final pod name => cavName-workloadName-q4m9c)
	if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobContent {
		if v := checkDerivedNameLength(cavObjNew.Name, workload.Name, "q4m9c", "content job pod name"); !v.allowed {
			return v
		}
	}

	return validAdmissionReviewObj()
}

func getWorkloadTypeCount(workloads []v1alpha1.WorkloadDetails) map[string]int {
	workloadTypeCount := make(map[string]int)

	for _, workload := range workloads {

		if workload.DeploymentDefinition != nil {
			workloadTypeCount[string(workload.DeploymentDefinition.Type)] += 1
		} else if workload.JobDefinition != nil {
			workloadTypeCount[string(workload.JobDefinition.Type)] += 1
		}
	}

	return workloadTypeCount
}

func IsServicesOnly(ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion) bool {
	// When CA isn't marked as ServicesOnly yet (reconcile hasn't fully completed) --> Determine ServicesOnly looking into tenant job workloads
	if ca.Status.ServicesOnly == nil {
		return !slices.ContainsFunc(cav.Spec.Workloads, func(wd v1alpha1.WorkloadDetails) bool {
			return wd.JobDefinition != nil && wd.JobDefinition.Type != v1alpha1.JobContent
		}) && ca.IsProviderEmpty()
	}

	return ca.IsServicesOnly()
}

func checkWorkloadTypeCount(ca *v1alpha1.CAPApplication, cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {

	workloadTypeCount := getWorkloadTypeCount(cavObjNew.Spec.Workloads)

	if !IsServicesOnly(ca, cavObjNew) {
		// tenant dependent scenario
		if workloadTypeCount[string(v1alpha1.DeploymentCAP)] != 1 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.DeploymentCAP, workloadTypeCount[string(v1alpha1.DeploymentCAP)], v1alpha1.DeploymentCAP),
			}
		}

		if workloadTypeCount[string(v1alpha1.DeploymentRouter)] != 1 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.DeploymentRouter, workloadTypeCount[string(v1alpha1.DeploymentRouter)], v1alpha1.DeploymentRouter),
			}
		}

		if workloadTypeCount[string(v1alpha1.JobTenantOperation)] == 0 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf(TenantOpMissingErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
			}
		}
	} else {
		// tenant independent scenario - no tenant operations / custom tenant operation allowed
		if workloadTypeCount[string(v1alpha1.JobTenantOperation)] != 0 || workloadTypeCount[string(v1alpha1.JobCustomTenantOperation)] != 0 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf(TenantOpJobWorkloadCountErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.JobTenantOperation, v1alpha1.JobCustomTenantOperation),
			}
		}
	}

	return validAdmissionReviewObj()
}

func getContentWorkloadNames(cavObjNew *v1alpha1.CAPApplicationVersion) []string {
	contentJobWorkloads := []string{}
	for _, workload := range cavObjNew.Spec.Workloads {
		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobContent {
			contentJobWorkloads = append(contentJobWorkloads, workload.Name)
		}
	}
	return contentJobWorkloads
}

func checkWorkloadContentJob(cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {

	contentJobWorkloads := getContentWorkloadNames(cavObjNew)

	if len(contentJobWorkloads) > 1 && cavObjNew.Spec.ContentJobs == nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s if there are more than one content job, contentJobs should be defined", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	// If there are more than 1 content jobs, then all of them must be part of ContentJobs
	if len(contentJobWorkloads) > 1 {
		for _, name := range contentJobWorkloads {
			if !slices.Contains(cavObjNew.Spec.ContentJobs, name) {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf("%s %s content job %s is not specified as part of ContentJobs", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, name),
				}
			}
		}
	}

	// All the jobs specified in contentJobWorkloads should be a valid content job
	if cavObjNew.Spec.ContentJobs != nil {
		for _, job := range cavObjNew.Spec.ContentJobs {
			if !slices.Contains(contentJobWorkloads, job) {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf("%s %s job %s specified as part of ContentJobs is not a valid content job", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, job),
				}
			}
		}
	}

	return validAdmissionReviewObj()
}

func getDeploymentPorts(cavObjNew *v1alpha1.CAPApplicationVersion) map[string][]int32 {
	deploymentPorts := make(map[string][]int32)

	for _, workload := range cavObjNew.Spec.Workloads {
		if workload.DeploymentDefinition == nil {
			continue
		}

		ports := []int32{}
		if len(workload.DeploymentDefinition.Ports) == 0 {
			switch workload.DeploymentDefinition.Type {
			case v1alpha1.DeploymentCAP:
				ports = append(ports, defaultServerPort) // adding default CAP port
			case v1alpha1.DeploymentRouter:
				ports = append(ports, defaultRouterPort) // adding default Router port
			}
		} else {
			for _, port := range workload.DeploymentDefinition.Ports {
				ports = append(ports, port.Port)
			}
		}

		deploymentPorts[workload.Name] = ports
	}

	return deploymentPorts
}

func checkServiceExposure(cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {
	// check that all the workload names and ports mentioned in service exposures are valid
	// check that there are no duplicate subdomains in service exposures

	seenSubdomains := make(map[string]struct{})
	deploymentPorts := getDeploymentPorts(cavObjNew)

	for _, serviceExposure := range cavObjNew.Spec.ServiceExposures {
		if _, ok := seenSubdomains[serviceExposure.SubDomain]; ok {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf(DuplicateServiceExposureSubDomainErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, serviceExposure.SubDomain),
			}
		}

		seenSubdomains[serviceExposure.SubDomain] = struct{}{}

		for _, route := range serviceExposure.Routes {
			ports, ok := deploymentPorts[route.WorkloadName]
			if !ok {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf(ServiceExposureWorkloadNameErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, route.WorkloadName, serviceExposure.SubDomain),
				}
			}
			if !slices.Contains(ports, route.Port) {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf(ServiceExposurePortErr, InvalidationMessage, v1alpha1.CAPApplicationVersionKind, route.Port, route.WorkloadName, serviceExposure.SubDomain),
				}
			}
		}
	}

	return validAdmissionReviewObj()
}

func validateWorkloads(ca *v1alpha1.CAPApplication, cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {
	seenWorkloadNames := make(map[string]struct{})
	for _, workload := range cavObjNew.Spec.Workloads {

		if !workloadNameRegex.MatchString(workload.Name) {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s Invalid workload name: %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workload.Name),
			}
		}

		if workloadNameLengthValidate := checkWorkloadNameLength(cavObjNew, &workload); !workloadNameLengthValidate.allowed {
			return workloadNameLengthValidate
		}

		if workloadTypeValidate := checkWorkloadType(&workload); !workloadTypeValidate.allowed {
			return workloadTypeValidate
		}

		if workloadPortValidate := checkWorkloadPort(&workload); !workloadPortValidate.allowed {
			return workloadPortValidate
		}

		if workloadPDBValidate := checkWorkloadPodDistruptionBudget(&workload); !workloadPDBValidate.allowed {
			return workloadPDBValidate
		}

		if _, ok := seenWorkloadNames[workload.Name]; ok {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate workload name: %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workload.Name),
			}
		}

		seenWorkloadNames[workload.Name] = struct{}{}
	}

	if workloadTypeCntValidate := checkWorkloadTypeCount(ca, cavObjNew); !workloadTypeCntValidate.allowed {
		return workloadTypeCntValidate
	}

	if workloadContentJobValidate := checkWorkloadContentJob(cavObjNew); !workloadContentJobValidate.allowed {
		return workloadContentJobValidate
	}

	return validAdmissionReviewObj()
}

func checkWorkloadPodDistruptionBudget(workloadDetails *v1alpha1.WorkloadDetails) validateResource {
	// Invalidate configurations that specify a selector for PDB --> This is done exclusively by Operator as the configuration is workload specific.
	if workloadDetails.DeploymentDefinition != nil && workloadDetails.DeploymentDefinition.PodDisruptionBudget != nil && workloadDetails.DeploymentDefinition.PodDisruptionBudget.Selector != nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s selector must not be specified for podDisrptionBudget config in workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workloadDetails.Name),
		}
	}

	return validAdmissionReviewObj()
}

func getTenantOperationsFromSpec(cavObjNew *v1alpha1.CAPApplicationVersion) map[string]int {
	specTenantOperationsCntMap := make(map[string]int)
	ops := cavObjNew.Spec.TenantOperations
	for _, ref := range append(append(append([]v1alpha1.TenantOperationWorkloadReference{}, ops.Provisioning...), ops.Deprovisioning...), ops.Upgrade...) {
		specTenantOperationsCntMap[ref.WorkloadName]++
	}
	return specTenantOperationsCntMap
}

func checkForTenantOpJob(tenantOperations []v1alpha1.TenantOperationWorkloadReference, tenantOperationWorkloadCntMap map[string]int) bool {
	return slices.ContainsFunc(tenantOperations, func(tenantOp v1alpha1.TenantOperationWorkloadReference) bool {
		return tenantOperationWorkloadCntMap[tenantOp.WorkloadName] > 0
	})
}

func validateWorkloadsinTenantOperations(allTenantOperationsWorkloadCntMap map[string]int, tenantOperationWorkloadCntMap map[string]int, cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {

	specTenantOperationsCntMap := getTenantOperationsFromSpec(cavObjNew)

	// If spec.tenantOperations is specified, the entries (for provisioning, upgrade and deprovisioning) must include all spec.workloads.jobDefinitions of type TenantOperation and CustomTenantOperation
	for workloadTenantOperation := range allTenantOperationsWorkloadCntMap {
		if specTenantOperationsCntMap[workloadTenantOperation] == 0 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s workload tenant operation %s is not specified in spec.tenantOperations", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, workloadTenantOperation),
			}
		}
	}

	// All the entries specified in spec.tenantOperations should be a valid workload of type TenantOperation or customTenantOperation
	for specTenantOperation := range specTenantOperationsCntMap {
		if allTenantOperationsWorkloadCntMap[specTenantOperation] == 0 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s %s specified in spec.tenantOperations is not a valid workload of type TenantOperation or CustomTenantOperation", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, specTenantOperation),
			}
		}
	}

	// If spec.tenantOperations are defined for provisioning, upgrade or deprovisioning, one of the operation must be a tenant operation
	ops := cavObjNew.Spec.TenantOperations
	for _, phase := range []struct {
		refs []v1alpha1.TenantOperationWorkloadReference
		name string
	}{
		{ops.Provisioning, "provisioning"},
		{ops.Upgrade, "upgrade"},
		{ops.Deprovisioning, "deprovisioning"},
	} {
		if phase.refs != nil && !checkForTenantOpJob(phase.refs, tenantOperationWorkloadCntMap) {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.%s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, phase.name),
			}
		}
	}

	return validAdmissionReviewObj()
}

func validateTenantOperations(cavObjNew *v1alpha1.CAPApplicationVersion) validateResource {
	// Check: If a jobDefinition of type CustomTenantOperation is part of the workloads, spec.tenantOperations must be specified. It is possible to omit spec.tenantOperations when there are no jobs of type CustomTenantOperation and only one job of type TenantOperation
	//		  If spec.tenantOperations is specified, the entries (for provisioning, upgrade and deprovisioning) must include all spec.workloads.jobDefinitions of type TenantOperation
	// 		  All the entries specified in spec.tenantOperations should be a valid workload of type TenantOperation or CustomTenantOperation
	tenantOperationWorkloadCntMap := make(map[string]int)
	allTenantOperationsWorkloadCntMap := make(map[string]int)
	hasCustomTenantOp := false
	for _, workload := range cavObjNew.Spec.Workloads {
		if workload.JobDefinition == nil {
			continue
		}
		switch workload.JobDefinition.Type {
		case v1alpha1.JobTenantOperation:
			tenantOperationWorkloadCntMap[workload.Name]++
			allTenantOperationsWorkloadCntMap[workload.Name]++
		case v1alpha1.JobCustomTenantOperation:
			hasCustomTenantOp = true
			allTenantOperationsWorkloadCntMap[workload.Name]++
		}
	}

	// It is possible to omit spec.tenantOperations when there are no jobs of type CustomTenantOperation
	if !hasCustomTenantOp && cavObjNew.Spec.TenantOperations == nil {
		return validAdmissionReviewObj()
	}

	// If a jobDefinition of type CustomTenantOperation is part of the workloads, spec.tenantOperations must be specified
	if hasCustomTenantOp && cavObjNew.Spec.TenantOperations == nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s - If a jobDefinition of type CustomTenantOperation is part of the workloads, then spec.tenantOperations must be specified", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	if workloadsinTenantOperationsValidate := validateWorkloadsinTenantOperations(allTenantOperationsWorkloadCntMap, tenantOperationWorkloadCntMap, cavObjNew); !workloadsinTenantOperationsValidate.allowed {
		return workloadsinTenantOperationsValidate
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) checkCAPAppExists(cavObjNew *v1alpha1.CAPApplicationVersion) (ca *v1alpha1.CAPApplication, validateRes validateResource) {
	app, err := wh.CrdClient.SmeV1alpha1().CAPApplications(cavObjNew.GetNamespace()).Get(context.TODO(), cavObjNew.Spec.CAPApplicationInstance, metav1.GetOptions{})
	if app == nil || err != nil {
		return nil, validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s no valid %s found for: %s.%s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, v1alpha1.CAPApplicationKind, cavObjNew.GetNamespace(), cavObjNew.GetName()),
		}
	}

	return app, validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPApplicationVersion(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	cavObjOld := v1alpha1.CAPApplicationVersion{}
	cavObjNew := v1alpha1.CAPApplicationVersion{}

	// Note: Object is nil for "DELETE" operation
	if admissionReview.Request.Operation == admissionv1.Create || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &cavObjNew, v1alpha1.CAPApplicationVersionKind); !validatedResource.allowed {
			return validatedResource
		}
	}

	// Note: OldObject is nil for "CONNECT" and "CREATE" operations
	if admissionReview.Request.Operation == admissionv1.Delete || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.OldObject.Raw, &cavObjOld, v1alpha1.CAPApplicationVersionKind); !validatedResource.allowed {
			return validatedResource
		}
	}

	// check: on create
	if admissionReview.Request.Operation == admissionv1.Create {
		return wh.checkCAVCreate(&cavObjNew)

	}

	// check: update on .Spec, using cmpopts.EquateEmpty() to consider nil and empty slices/maps as equal (Eg: spec.ContentJobs)
	if admissionReview.Request.Operation == admissionv1.Update && !cmp.Equal(cavObjOld.Spec, cavObjNew.Spec, cmpopts.EquateEmpty()) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s spec cannot be modified for: %s.%s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, cavObjNew.GetNamespace(), cavObjNew.GetName()),
		}
	}
	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) checkCAVCreate(cav *v1alpha1.CAPApplicationVersion) validateResource {
	// Check: CAPApplication exists
	ca, capAppExistsValidate := wh.checkCAPAppExists(cav)
	if !capAppExistsValidate.allowed {
		return capAppExistsValidate
	}

	if workloadValidate := validateWorkloads(ca, cav); !workloadValidate.allowed {
		return workloadValidate
	}

	if serviceExposureValidate := checkServiceExposure(cav); !serviceExposureValidate.allowed {
		return serviceExposureValidate
	}

	return validateTenantOperations(cav)
}

func (wh *WebhookHandler) checkCaIsConsistent(catObjOld v1alpha1.CAPTenant) validateResource {

	ca, err := wh.CrdClient.SmeV1alpha1().CAPApplications(catObjOld.GetNamespace()).Get(context.TODO(), catObjOld.Spec.CAPApplicationInstance, metav1.GetOptions{})

	if ca != nil && err == nil && !ca.IsProviderEmpty() && ca.Status.State == v1alpha1.CAPApplicationStateConsistent && catObjOld.GetLabels()[LabelTenantType] == ProviderTenantType && catObjOld.Status.State == v1alpha1.CAPTenantStateReady {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s provider %s %s cannot be deleted when a consistent %s %s exists. Delete the %s or remove it's provider section instead to delete this tenant", InvalidationMessage, v1alpha1.CAPTenantKind, catObjOld.Name, v1alpha1.CAPApplicationKind, ca.Name, v1alpha1.CAPApplicationKind),
		}
	}
	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) checkForDuplicateDomains(domain, name string) validateResource {
	clusterDoms, _ := wh.CrdClient.SmeV1alpha1().ClusterDomains(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	for _, clusterDom := range clusterDoms.Items {
		if clusterDom.Spec.Domain == domain && clusterDom.Name != name {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s %s already exist with domain %s", InvalidationMessage, v1alpha1.ClusterDomainKind, clusterDom.Name, domain),
			}
		}
	}

	doms, _ := wh.CrdClient.SmeV1alpha1().Domains(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	for _, dom := range doms.Items {
		if dom.Spec.Domain == domain && dom.Name != name {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s %s already exist in namespace %s with domain %s", InvalidationMessage, v1alpha1.DomainKind, dom.Name, dom.Namespace, domain),
			}
		}
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateClusterDomain(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	clusterDomObjNew := v1alpha1.ClusterDomain{}
	if admissionReview.Request.Operation == admissionv1.Create || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &clusterDomObjNew, v1alpha1.ClusterDomainKind); !validatedResource.allowed {
			return validatedResource
		}

		// Check if a clusterDomain or Domain already exists with the new domain
		return wh.checkForDuplicateDomains(clusterDomObjNew.Spec.Domain, clusterDomObjNew.Name)
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateDomain(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	domObjNew := v1alpha1.Domain{}
	if admissionReview.Request.Operation == admissionv1.Create || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &domObjNew, v1alpha1.DomainKind); !validatedResource.allowed {
			return validatedResource
		}

		// Check if a clusterDomain or Domain already exists with the new domain
		return wh.checkForDuplicateDomains(domObjNew.Spec.Domain, domObjNew.Name)
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPTenant(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	catObjOld := v1alpha1.CAPTenant{}
	catObjNew := v1alpha1.CAPTenant{}

	// Note: Object is nil for "DELETE" operation
	if admissionReview.Request.Operation == admissionv1.Create || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &catObjNew, v1alpha1.CAPTenantKind); !validatedResource.allowed {
			return validatedResource
		}
	}
	// Note: OldObject is nil for "CONNECT" and "CREATE" operations
	if admissionReview.Request.Operation == admissionv1.Delete || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.OldObject.Raw, &catObjOld, v1alpha1.CAPTenantKind); !validatedResource.allowed {
			return validatedResource
		}
	}

	// check: CAPApplication exists on create
	if admissionReview.Request.Operation == admissionv1.Create {
		if app, err := wh.CrdClient.SmeV1alpha1().CAPApplications(catObjNew.GetNamespace()).Get(context.TODO(), catObjNew.Spec.CAPApplicationInstance, metav1.GetOptions{}); app == nil || err != nil {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s no valid %s found for: %s.%s", InvalidationMessage, v1alpha1.CAPTenantKind, v1alpha1.CAPApplicationKind, catObjNew.GetNamespace(), catObjNew.GetName()),
			}
		}
	}
	// check: update on .Spec.CapApplicationInstance
	if admissionReview.Request.Operation == admissionv1.Update && catObjOld.Spec.CAPApplicationInstance != catObjNew.Spec.CAPApplicationInstance {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s capApplicationInstance value cannot be modified for: %s.%s", InvalidationMessage, v1alpha1.CAPTenantKind, catObjNew.GetNamespace(), catObjNew.GetName()),
		}
	}

	// check: dont allow provider tenant deletion when CA is consistent
	if admissionReview.Request.Operation == admissionv1.Delete {
		return wh.checkCaIsConsistent(catObjOld)
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPTenantOutput(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	ctoutObjNew := v1alpha1.CAPTenantOutput{}

	if admissionReview.Request.Operation == admissionv1.Delete {
		return validAdmissionReviewObj()
	}

	if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &ctoutObjNew, v1alpha1.CAPTenantOutputKind); !validatedResource.allowed {
		return validatedResource
	}

	tenantId, exists := ctoutObjNew.Labels[LabelTenantId]
	if !exists {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s label %s missing on CAP tenant output %s", InvalidationMessage, v1alpha1.CAPTenantOutputKind, LabelTenantId, ctoutObjNew.Name),
		}
	}

	labelSelector, _ := labels.ValidatedSelectorFromSet(map[string]string{LabelTenantId: tenantId})
	ctList, err := wh.CrdClient.SmeV1alpha1().CAPTenants(ctoutObjNew.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector.String()})
	if err != nil || len(ctList.Items) == 0 {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s label %s on CAP tenant output %s does not contain a valid tenant ID", InvalidationMessage, v1alpha1.CAPTenantOutputKind, LabelTenantId, ctoutObjNew.Name),
		}
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPApplication(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	caObjOld := v1alpha1.CAPApplication{}
	caObjNew := v1alpha1.CAPApplication{}

	// Note: OldObject is nil for "CONNECT" and "CREATE" operations
	if admissionReview.Request.Operation == admissionv1.Delete || admissionReview.Request.Operation == admissionv1.Update {
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.OldObject.Raw, &caObjOld, v1alpha1.CAPApplicationKind); !validatedResource.allowed {
			return validatedResource
		}
	}
	if admissionReview.Request.Operation == admissionv1.Update || admissionReview.Request.Operation == admissionv1.Create {
		// Note: Object is nil for "DELETE" operation
		if validatedResource := unmarshalRawObj(w, admissionReview.Request.Object.Raw, &caObjNew, v1alpha1.CAPApplicationKind); !validatedResource.allowed {
			return validatedResource
		}
	}

	// check: update on .Spec.Provider - removing is allowed, but adding or changing existing value is not (deprecated)
	if admissionReview.Request.Operation == admissionv1.Update && !caObjNew.IsProviderEmpty() && !cmp.Equal(caObjNew.Spec.Provider, caObjOld.Spec.Provider) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s provider details cannot be changed for: %s.%s", InvalidationMessage, v1alpha1.CAPApplicationKind, caObjNew.GetNamespace(), caObjNew.GetName()),
		}
	}

	// Domains are DEPRECATED
	if admissionReview.Request.Operation == admissionv1.Create && !cmp.Equal(caObjNew.Spec.Domains, v1alpha1.ApplicationDomains{}) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf(DomainsDeprecated, InvalidationMessage, v1alpha1.CAPApplicationKind, caObjNew.GetNamespace(), caObjNew.GetName()),
		}
	}

	// check: cannot switch from domainRefs to domains
	if admissionReview.Request.Operation == admissionv1.Update && (len(caObjOld.Spec.DomainRefs) > 0 && !cmp.Equal(caObjNew.Spec.Domains, v1alpha1.ApplicationDomains{})) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf(DomainsDeprecated, InvalidationMessage, v1alpha1.CAPApplicationKind, caObjNew.GetNamespace(), caObjNew.GetName()),
		}
	}

	return validAdmissionReviewObj()
}

func unmarshalRawObj(w http.ResponseWriter, rawBytes []byte, response any, resourceKind string) validateResource {
	if err := json.Unmarshal(rawBytes, response); err != nil {
		return invalidAdmissionReviewObj(w, resourceKind, err)
	}
	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) Validate(w http.ResponseWriter, r *http.Request) {
	// read incoming request to bytes
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %w", AdmissionError, err))
		return
	}

	// create admission review from bytes
	admissionReview := getAdmissionRequestFromBytes(w, body)
	if admissionReview == nil {
		return
	}

	klog.InfoS("incoming admission review", "kind", admissionReview.Request.Kind.Kind)

	validation := validAdmissionReviewObj()

	switch admissionReview.Request.Kind.Kind {
	case v1alpha1.CAPApplicationVersionKind:
		validation = wh.validateCAPApplicationVersion(w, admissionReview)
	case v1alpha1.CAPTenantKind:
		validation = wh.validateCAPTenant(w, admissionReview)
	case v1alpha1.CAPApplicationKind:
		validation = wh.validateCAPApplication(w, admissionReview)
	case v1alpha1.CAPTenantOutputKind:
		validation = wh.validateCAPTenantOutput(w, admissionReview)
	case v1alpha1.ClusterDomainKind:
		validation = wh.validateClusterDomain(w, admissionReview)
	case v1alpha1.DomainKind:
		validation = wh.validateDomain(w, admissionReview)
	}

	if validation.errorOccured {
		return
	}

	// prepare response
	responseBytes := prepareResponse(w, admissionReview, validation)
	if responseBytes == nil {
		return
	}
	w.Write(responseBytes)
}

func getAdmissionRequestFromBytes(w http.ResponseWriter, body []byte) *admissionv1.AdmissionReview {
	admissionReview := admissionv1.AdmissionReview{}
	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReview); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("%s %w", AdmissionError, err))
		return nil
	} else if admissionReview.Request == nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("%s empty request", AdmissionError))
		return nil
	}
	return &admissionReview
}

func prepareResponse(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview, validation validateResource) []byte {
	// prepare response object
	finalizedAdmissionReview := admissionv1.AdmissionReview{}
	finalizedAdmissionReview.Kind = admissionReview.Kind
	finalizedAdmissionReview.APIVersion = admissionReview.APIVersion
	finalizedAdmissionReview.Response = &admissionv1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: validation.allowed,
	}

	message := ValidationMessage
	if !validation.allowed {
		finalizedAdmissionReview.Response.Result = &metav1.Status{
			Message: validation.message,
		}
		message = InvalidationMessage
	}
	klog.InfoS(message, "kind", admissionReview.Request.Kind.Kind, "operation", string(admissionReview.Request.Operation), "details", validation.message)

	bytes, err := json.Marshal(&finalizedAdmissionReview)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %w", AdmissionError, err))
		return nil
	}
	return bytes
}

func httpError(w http.ResponseWriter, code int, err error) {
	klog.ErrorS(err, err.Error())
	http.Error(w, err.Error(), code)
}

func invalidAdmissionReviewObj(w http.ResponseWriter, kind string, sourceErr error) validateResource {
	httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %s %s %w", InvalidResource, kind, AdmissionError, sourceErr))
	return validateResource{errorOccured: true}
}

func validAdmissionReviewObj() validateResource {
	return validateResource{allowed: true}
}
