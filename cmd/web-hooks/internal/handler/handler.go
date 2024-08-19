/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	"golang.org/x/exp/slices"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"
)

const (
	LabelTenantType             = "sme.sap.com/tenant-type"
	ProviderTenantType          = "provider"
	SideCarEnv                  = "WEBHOOK_SIDE_CAR"
	AdmissionError              = "admission error:"
	InvalidResource             = "invalid resource"
	InvalidationMessage         = "invalidated from webhook"
	ValidationMessage           = "validated from webhook"
	RequestPath                 = "/request"
	DeploymentWorkloadCountErr  = "%s %s there should always be one workload deployment definition of type %s. Currently, there are %d workloads of type %s"
	JobWorkloadCountErr         = "%s %s there should always be one workload job definition of type %s. Currently, there are %d workloads of type %s"
	TenantOpJobWorkloadCountErr = "%s %s there should not be more than one workload job definition of type %s. Currently, there are %d workloads of type %s"
)

type validateResource struct {
	errorOccured bool
	allowed      bool
	message      string
}

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

type WebhookHandler struct {
	CrdClient versioned.Interface
}

// Metadata struct for parsing
type Metadata struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type ResponseCat struct {
	Metadata `json:"metadata"`
	Spec     *v1alpha1.CAPTenantSpec   `json:"spec"`
	Status   *v1alpha1.CAPTenantStatus `json:"status"`
	Kind     string                    `json:"kind"`
}

type ResponseCav struct {
	Metadata `json:"metadata"`
	Spec     *v1alpha1.CAPApplicationVersionSpec `json:"spec"`
	Kind     string                              `json:"kind"`
}

type ResponseCa struct {
	Metadata `json:"metadata"`
	Spec     *v1alpha1.CAPApplicationSpec `json:"spec"`
	Kind     string                       `json:"kind"`
}

type responseInterface interface {
	isEmpty() bool
}

func (m Metadata) isEmpty() bool {
	return m.Name == ""
}

func checkWorkloadPort(workload *v1alpha1.WorkloadDetails) validateResource {
	if workload.DeploymentDefinition == nil {
		return validAdmissionReviewObj()
	}

	if len(workload.DeploymentDefinition.Ports) == 0 {
		return validAdmissionReviewObj()
	}

	// Checks-
	// at least one port configuration should have routerDestinationName defined
	// port name and port number should be unique
	uniquePortNameCountMap := make(map[string]int)
	uniquePortNumCountMap := make(map[string]int)
	routerDestinationNameFound := false
	for _, port := range workload.DeploymentDefinition.Ports {
		if port.RouterDestinationName != "" {
			routerDestinationNameFound = true
		}
		uniquePortNameCountMap[port.Name] += 1
		uniquePortNumCountMap[strconv.Itoa(int(port.Port))] += 1
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

	for portName, cnt := range uniquePortNameCountMap {
		if cnt > 1 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate port name: %s in workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, portName, workload.Name),
			}
		}
	}

	for portNum, cnt := range uniquePortNumCountMap {
		if cnt > 1 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate port number: %s in workload - %s", InvalidationMessage, v1alpha1.CAPApplicationVersionKind, portNum, workload.Name),
			}
		}
	}

	return validAdmissionReviewObj()
}

func checkWorkloadType(workload *v1alpha1.WorkloadDetails) validateResource {
	if workload.DeploymentDefinition != nil && workload.DeploymentDefinition.Type != v1alpha1.DeploymentCAP && workload.DeploymentDefinition.Type != v1alpha1.DeploymentRouter && workload.DeploymentDefinition.Type != v1alpha1.DeploymentAdditional {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s invalid deployment definition type. Only supported - CAP, Router and Additional", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	if workload.JobDefinition != nil && workload.JobDefinition.Type != v1alpha1.JobContent && workload.JobDefinition.Type != v1alpha1.JobTenantOperation && workload.JobDefinition.Type != v1alpha1.JobCustomTenantOperation {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s invalid job definition type. Only supported - Content, TenantOperation and CustomTenantOperation", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	return validAdmissionReviewObj()
}

func getWorkloadTypeCount(workloads []v1alpha1.WorkloadDetails) map[string]int {
	workloadTypeCount := make(map[string]int)
	for _, workload := range workloads {
		if workload.DeploymentDefinition != nil && workload.DeploymentDefinition.Type == v1alpha1.DeploymentCAP {
			workloadTypeCount[string(v1alpha1.DeploymentCAP)] += 1
		}

		if workload.DeploymentDefinition != nil && workload.DeploymentDefinition.Type == v1alpha1.DeploymentRouter {
			workloadTypeCount[string(v1alpha1.DeploymentRouter)] += 1
		}

		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobContent {
			workloadTypeCount[string(v1alpha1.JobContent)] += 1
		}

		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobTenantOperation {
			workloadTypeCount[string(v1alpha1.JobTenantOperation)] += 1
		}
	}

	return workloadTypeCount
}

func checkWorkloadTypeCount(cavObjNew *ResponseCav) validateResource {

	workloadTypeCount := getWorkloadTypeCount(cavObjNew.Spec.Workloads)

	if workloadTypeCount[string(v1alpha1.DeploymentCAP)] != 1 {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, cavObjNew.Kind, v1alpha1.DeploymentCAP, workloadTypeCount[string(v1alpha1.DeploymentCAP)], v1alpha1.DeploymentCAP),
		}
	}

	if workloadTypeCount[string(v1alpha1.DeploymentRouter)] != 1 {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf(DeploymentWorkloadCountErr, InvalidationMessage, cavObjNew.Kind, v1alpha1.DeploymentRouter, workloadTypeCount[string(v1alpha1.DeploymentRouter)], v1alpha1.DeploymentRouter),
		}
	}

	return validAdmissionReviewObj()
}

func getContentWorkloadNames(cavObjNew *ResponseCav) []string {
	contentJobWorkloads := []string{}
	for _, workload := range cavObjNew.Spec.Workloads {
		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobContent {
			contentJobWorkloads = append(contentJobWorkloads, workload.Name)
		}
	}
	return contentJobWorkloads
}

func checkWorkloadContentJob(cavObjNew *ResponseCav) validateResource {

	contentJobWorkloads := getContentWorkloadNames(cavObjNew)

	if len(contentJobWorkloads) > 1 && cavObjNew.Spec.ContentJobs == nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s if there are more than one content job, contentJobs should be defined", InvalidationMessage, cavObjNew.Kind),
		}
	}

	// If there are more than 1 content jobs, then all of them must be part of ContentJobs
	if len(contentJobWorkloads) > 1 {
		for _, name := range contentJobWorkloads {
			if !slices.ContainsFunc(cavObjNew.Spec.ContentJobs, func(job string) bool { return job == name }) {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf("%s %s content job %s is not specified as part of ContentJobs", InvalidationMessage, cavObjNew.Kind, name),
				}
			}
		}
	}

	// All the jobs specified in contentJobWorkloads should be a valid content job
	if cavObjNew.Spec.ContentJobs != nil {
		for _, job := range cavObjNew.Spec.ContentJobs {
			if !slices.ContainsFunc(contentJobWorkloads, func(name string) bool { return name == job }) {
				return validateResource{
					allowed: false,
					message: fmt.Sprintf("%s %s job %s specified as part of ContentJobs is not a valid content job", InvalidationMessage, cavObjNew.Kind, job),
				}
			}
		}
	}

	return validAdmissionReviewObj()
}

func validateWorkloads(cavObjNew *ResponseCav) validateResource {
	// Check: Workload name should be unique
	//		  Only one workload deployment of type CAP, router and content is allowed
	uniqueWorkloadNameCountMap := make(map[string]int)
	for _, workload := range cavObjNew.Spec.Workloads {

		if workloadTypeValidate := checkWorkloadType(&workload); !workloadTypeValidate.allowed {
			return workloadTypeValidate
		}

		if workloadPortValidate := checkWorkloadPort(&workload); !workloadPortValidate.allowed {
			return workloadPortValidate
		}

		// get count of workload names
		uniqueWorkloadNameCountMap[workload.Name] += 1
	}

	for workloadName, cnt := range uniqueWorkloadNameCountMap {
		if cnt > 1 {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s duplicate workload name: %s", InvalidationMessage, cavObjNew.Kind, workloadName),
			}
		}
	}

	if workloadTypeCntValidate := checkWorkloadTypeCount(cavObjNew); !workloadTypeCntValidate.allowed {
		return workloadTypeCntValidate
	}

	if workloadContentJobValidate := checkWorkloadContentJob(cavObjNew); !workloadContentJobValidate.allowed {
		return workloadContentJobValidate
	}

	return validAdmissionReviewObj()
}

func getTenantOperationsFromSpec(cavObjNew *ResponseCav) map[string]int {
	specTenantOperationsCntMap := make(map[string]int)
	var tenantOperationsList []v1alpha1.TenantOperationWorkloadReference
	if cavObjNew.Spec.TenantOperations.Provisioning != nil {
		tenantOperationsList = append(tenantOperationsList, cavObjNew.Spec.TenantOperations.Provisioning...)
	}

	if cavObjNew.Spec.TenantOperations.Deprovisioning != nil {
		tenantOperationsList = append(tenantOperationsList, cavObjNew.Spec.TenantOperations.Deprovisioning...)
	}

	if cavObjNew.Spec.TenantOperations.Upgrade != nil {
		tenantOperationsList = append(tenantOperationsList, cavObjNew.Spec.TenantOperations.Upgrade...)
	}

	for _, tenantOperation := range tenantOperationsList {
		specTenantOperationsCntMap[tenantOperation.WorkloadName] += 1
	}
	return specTenantOperationsCntMap
}

func checkForTenantOpJob(tenantOperations []v1alpha1.TenantOperationWorkloadReference, tenantOperationWorkloadCntMap map[string]int) bool {
	return slices.ContainsFunc(tenantOperations, func(tenantOp v1alpha1.TenantOperationWorkloadReference) bool {
		return tenantOperationWorkloadCntMap[tenantOp.WorkloadName] > 0
	})
}

func validateWorkloadsinTenantOperations(allTenantOperationsWorkloadCntMap map[string]int, tenantOperationWorkloadCntMap map[string]int, cavObjNew *ResponseCav) validateResource {

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
	if cavObjNew.Spec.TenantOperations.Provisioning != nil && !checkForTenantOpJob(cavObjNew.Spec.TenantOperations.Provisioning, tenantOperationWorkloadCntMap) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.provisioning", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	if cavObjNew.Spec.TenantOperations.Upgrade != nil && !checkForTenantOpJob(cavObjNew.Spec.TenantOperations.Upgrade, tenantOperationWorkloadCntMap) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.upgrade", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	if cavObjNew.Spec.TenantOperations.Deprovisioning != nil && !checkForTenantOpJob(cavObjNew.Spec.TenantOperations.Deprovisioning, tenantOperationWorkloadCntMap) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s - No tenant operation specified in spec.tenantOperation.deprovisioning", InvalidationMessage, v1alpha1.CAPApplicationVersionKind),
		}
	}

	return validAdmissionReviewObj()
}

func validateTenantOperations(cavObjNew *ResponseCav) validateResource {
	// Check: If a jobDefinition of type CustomTenantOperation is part of the workloads, spec.tenantOperations must be specified. It is possible to omit spec.tenantOperations when there are no jobs of type CustomTenantOperation and only one job of type TenantOperation
	//		  If spec.tenantOperations is specified, the entries (for provisioning, upgrade and deprovisioning) must include all spec.workloads.jobDefinitions of type TenantOperation
	// 		  All the entries specified in spec.tenantOperations should be a valid workload of type TenantOperation or CustomTenantOperation
	tenantOperationWorkloadCntMap := make(map[string]int)
	allTenantOperationsWorkloadCntMap := make(map[string]int)
	customTenantOpWorkloadCntMap := make(map[string]int)
	for _, workload := range cavObjNew.Spec.Workloads {
		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobTenantOperation {
			tenantOperationWorkloadCntMap[workload.Name] += 1
			allTenantOperationsWorkloadCntMap[workload.Name] += 1
		}

		if workload.JobDefinition != nil && workload.JobDefinition.Type == v1alpha1.JobCustomTenantOperation {
			customTenantOpWorkloadCntMap[workload.Name] += 1
			allTenantOperationsWorkloadCntMap[workload.Name] += 1
		}
	}

	// It is possible to omit spec.tenantOperations when there are no jobs of type CustomTenantOperation and only one job of type TenantOperation
	if len(customTenantOpWorkloadCntMap) == 0 && cavObjNew.Spec.TenantOperations == nil {
		return validAdmissionReviewObj()
	}

	// If a jobDefinition of type CustomTenantOperation is part of the workloads, spec.tenantOperations must be specified
	if len(customTenantOpWorkloadCntMap) > 0 && cavObjNew.Spec.TenantOperations == nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s - If a jobDefinition of type CustomTenantOperation is part of the workloads, then spec.tenantOperations must be specified", InvalidationMessage, cavObjNew.Kind),
		}
	}

	if cavObjNew.Spec.TenantOperations == nil {
		return validAdmissionReviewObj()
	}

	if workloadsinTenantOperationsValidate := validateWorkloadsinTenantOperations(allTenantOperationsWorkloadCntMap, tenantOperationWorkloadCntMap, cavObjNew); !workloadsinTenantOperationsValidate.allowed {
		return workloadsinTenantOperationsValidate
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) checkCAPAppExists(cavObjNew *ResponseCav) validateResource {
	if app, err := wh.CrdClient.SmeV1alpha1().CAPApplications(cavObjNew.Metadata.Namespace).Get(context.TODO(), cavObjNew.Spec.CAPApplicationInstance, metav1.GetOptions{}); app == nil || err != nil {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s no valid %s found for: %s.%s", InvalidationMessage, cavObjNew.Kind, v1alpha1.CAPApplicationKind, cavObjNew.Metadata.Namespace, cavObjNew.Metadata.Name),
		}
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPApplicationVersion(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	cavObjOld := ResponseCav{}
	cavObjNew := ResponseCav{}

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
		// Check: CAPApplication exists
		if capAppExistsValidate := wh.checkCAPAppExists(&cavObjNew); !capAppExistsValidate.allowed {
			return capAppExistsValidate
		}

		if workloadValidate := validateWorkloads(&cavObjNew); !workloadValidate.allowed {
			return workloadValidate
		}

		return validateTenantOperations(&cavObjNew)

	}

	// check: update on .Spec
	if admissionReview.Request.Operation == admissionv1.Update && !cmp.Equal(cavObjOld.Spec, cavObjNew.Spec) {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s spec cannot be modified for: %s.%s", InvalidationMessage, cavObjNew.Kind, cavObjNew.Metadata.Namespace, cavObjNew.Metadata.Name),
		}
	}
	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) checkCaIsConsistent(catObjOld ResponseCat) validateResource {

	ca, err := wh.CrdClient.SmeV1alpha1().CAPApplications(catObjOld.Metadata.Namespace).Get(context.TODO(), catObjOld.Spec.CAPApplicationInstance, metav1.GetOptions{})

	if ca != nil && err == nil && ca.Status.State == v1alpha1.CAPApplicationStateConsistent && catObjOld.Metadata.Labels[LabelTenantType] == ProviderTenantType && catObjOld.Status.State == v1alpha1.CAPTenantStateReady {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s provider %s %s cannot be deleted when a consistent %s %s exists. Delete the %s instead to delete all tenants", InvalidationMessage, catObjOld.Kind, catObjOld.Name, v1alpha1.CAPApplicationKind, ca.Name, v1alpha1.CAPApplicationKind),
		}
	}
	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPTenant(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	catObjOld := ResponseCat{}
	catObjNew := ResponseCat{}

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
		if app, err := wh.CrdClient.SmeV1alpha1().CAPApplications(catObjNew.Metadata.Namespace).Get(context.TODO(), catObjNew.Spec.CAPApplicationInstance, metav1.GetOptions{}); app == nil || err != nil {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s no valid %s found for: %s.%s", InvalidationMessage, catObjNew.Kind, v1alpha1.CAPApplicationKind, catObjNew.Metadata.Namespace, catObjNew.Metadata.Name),
			}
		}
	}
	// check: update on .Spec.CapApplicationInstance
	if admissionReview.Request.Operation == admissionv1.Update && catObjOld.Spec.CAPApplicationInstance != catObjNew.Spec.CAPApplicationInstance {
		return validateResource{
			allowed: false,
			message: fmt.Sprintf("%s %s capApplicationInstance value cannot be modified for: %s.%s", InvalidationMessage, catObjNew.Kind, catObjNew.Metadata.Namespace, catObjNew.Metadata.Name),
		}
	}

	// check: dont allow provider tenant deletion when CA is consistent
	if admissionReview.Request.Operation == admissionv1.Delete {
		return wh.checkCaIsConsistent(catObjOld)
	}

	return validAdmissionReviewObj()
}

func (wh *WebhookHandler) validateCAPApplication(w http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) validateResource {
	caObjOld := ResponseCa{}
	caObjNew := ResponseCa{}

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
		// check: update on .Spec.Provider
		if admissionReview.Request.Operation == admissionv1.Update && !cmp.Equal(caObjNew.Spec.Provider, caObjOld.Spec.Provider) {
			return validateResource{
				allowed: false,
				message: fmt.Sprintf("%s %s provider details cannot be changed for: %s.%s", InvalidationMessage, caObjNew.Kind, caObjNew.Metadata.Namespace, caObjNew.Metadata.Name),
			}
		}
	}
	return validAdmissionReviewObj()
}

func unmarshalRawObj(w http.ResponseWriter, rawBytes []byte, response responseInterface, resourceKind string) validateResource {
	if err := json.Unmarshal(rawBytes, response); err != nil || response.isEmpty() {
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

	// sidecar
	if !enableSidecar(w, body) {
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
		if validation = wh.validateCAPApplicationVersion(w, admissionReview); validation.errorOccured {
			return
		}
	case v1alpha1.CAPTenantKind:
		if validation = wh.validateCAPTenant(w, admissionReview); validation.errorOccured {
			return
		}
	case v1alpha1.CAPApplicationKind:
		if validation = wh.validateCAPApplication(w, admissionReview); validation.errorOccured {
			return
		}
	}

	// prepare response
	if responseBytes := prepareResponse(w, admissionReview, validation); responseBytes == nil {
		return
	} else {
		w.Write(responseBytes)
	}
}

func enableSidecar(w http.ResponseWriter, body []byte) bool {
	// write request to volume mount - if side car is enabled
	sidecarEnv := os.Getenv(SideCarEnv)

	if sidecarEnv != "" {
		if sidecarEnabled, err := strconv.ParseBool(sidecarEnv); err != nil {
			httpError(w, http.StatusInternalServerError, fmt.Errorf("sidecar env read error: %w", err))
			return false
		} else if sidecarEnabled {
			if err = os.WriteFile(os.TempDir()+RequestPath, body, 0644); err != nil {
				httpError(w, http.StatusInternalServerError, fmt.Errorf("request object write error: %w", err))
				return false
			}
		}
	}
	return true
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
	finalizedAdmissionReview := v1beta1.AdmissionReview{}
	finalizedAdmissionReview.Kind = admissionReview.Kind
	finalizedAdmissionReview.APIVersion = admissionReview.APIVersion
	finalizedAdmissionReview.Response = &v1beta1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: validation.allowed,
	}
	finalizedAdmissionReview.APIVersion = admissionReview.APIVersion

	message := ValidationMessage
	if !validation.allowed {
		finalizedAdmissionReview.Response.Result = &metav1.Status{
			Message: validation.message,
		}
		message = InvalidationMessage
	}
	klog.InfoS(message, "kind", admissionReview.Request.Kind.Kind, "operation", string(admissionReview.Request.Operation))

	if bytes, err := json.Marshal(&finalizedAdmissionReview); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("%s %w", AdmissionError, err))
		return nil
	} else {
		return bytes
	}
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
