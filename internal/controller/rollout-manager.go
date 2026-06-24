/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sap/cap-operator/internal/util"
	"github.com/sap/cap-operator/pkg/apis/sme.sap.com/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	EnvRolloutDelay     = "ROLLOUT_DELAY"
	defaultRolloutDelay = time.Hour
	minRolloutDelay     = 30 * time.Second
)

// getRolloutDelay returns the rollout delay from the ROLLOUT_DELAY env var.
// Falls back to defaultRolloutDelay if unset or unparseable.
// Values below minRolloutDelay are clamped to minRolloutDelay.
func getRolloutDelay() time.Duration {
	if v, ok := os.LookupEnv(EnvRolloutDelay); ok {
		dur, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			klog.ErrorS(nil, "Invalid ROLLOUT_DELAY value; using default", "value", v, "default", defaultRolloutDelay)
			return defaultRolloutDelay
		}
		if dur < minRolloutDelay {
			klog.ErrorS(nil, "ROLLOUT_DELAY below minimum; using minimum", "value", dur, "minimum", minRolloutDelay)
			return minRolloutDelay
		}
		return dur
	}
	return defaultRolloutDelay
}

// rolloutManager batches credential-rotation work per namespace.
// The informer calls Enqueue(namespace, secretName) for every changed BTP service secret.
// Items are placed on the delaying queue with a rolloutDelay (default 1-hour) window;
// multiple Enqueue calls within this window for the same namespace are collected and
// processed once by the queue by accumulating all secret names in pendingSecrets.
// When the queue item reconciles, only workloads that consume the service affected by
// one of those secrets are rolled out.
type rolloutManager struct {
	queue          workqueue.TypedRateLimitingInterface[string]
	ctrl           *Controller
	mu             sync.Mutex
	pendingSecrets map[string]map[string]struct{} // namespace -> set of secret names
	rolloutDelay   time.Duration
}

func newRolloutManager(ctrl *Controller) *rolloutManager {
	return &rolloutManager{
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "rollout-manager"},
		),
		ctrl:           ctrl,
		pendingSecrets: map[string]map[string]struct{}{},
		rolloutDelay:   getRolloutDelay(),
	}
}

// records secretName as pending for namespace and schedules a delayed rollout pass.
// Duplicate namespaces within the delay window are collected to be processed once by the queue.
func (m *rolloutManager) Enqueue(namespace, secretName string) {
	m.mu.Lock()
	if m.pendingSecrets[namespace] == nil {
		m.pendingSecrets[namespace] = map[string]struct{}{}
	}
	m.pendingSecrets[namespace][secretName] = struct{}{}
	m.mu.Unlock()

	m.queue.AddAfter(namespace, m.rolloutDelay)
}

// atomically removes and returns the accumulated secret names for the given namespace
func (m *rolloutManager) drainSecrets(namespace string) map[string]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	secrets := m.pendingSecrets[namespace]
	delete(m.pendingSecrets, namespace)
	return secrets
}

// merges secrets back into pendingSecrets so a re-queued item still has data to process
func (m *rolloutManager) restoreSecrets(namespace string, secrets map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingSecrets[namespace] == nil {
		m.pendingSecrets[namespace] = map[string]struct{}{}
	}
	for s := range secrets {
		m.pendingSecrets[namespace][s] = struct{}{}
	}
}

func (m *rolloutManager) Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		m.queue.ShutDown()
	}()

	concurrency := getConcurrencyForResource(ResourceCAPApplicationVersion)
	klog.InfoS("starting rollout manager", "concurrency", concurrency)

	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			for {
				ns, shutdown := m.queue.Get()
				if shutdown {
					return
				}
				affectedSecrets := m.drainSecrets(ns)
				klog.InfoS("processing credential rotation", "namespace", ns, "secrets", len(affectedSecrets))
				if err := m.processNamespace(ctx, ns, affectedSecrets); err != nil {
					util.LogError(err, "error processing credential rotation", "processNamespace", nil, nil, "namespace", ns)
					m.restoreSecrets(ns, affectedSecrets)
					m.queue.AddRateLimited(ns)
				} else {
					m.queue.Forget(ns)
				}
				m.queue.Done(ns)
			}
		})
	}

	// On startup, enqueue namespace/secrets from all relevant CAs, to potentially cover missed updates during a crash.
	if err := m.enqueuePendingRollouts(); err != nil {
		util.LogError(err, "error during startup rollout check", "rolloutManager", nil, nil)
	}

	wg.Wait()
	klog.InfoS("rollout manager stopped")
}

// enqueue namespace/secrets from all relevant CAs (RolloutOnCredentialUpdate=true), to potentially handle missed updates (e.g. during a crash)
func (m *rolloutManager) enqueuePendingRollouts() error {
	cas, err := m.ctrl.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error listing CAPApplications for startup rollout check: %w", err)
	}

	// namespace -> set of secret names referenced by relevant CAs
	pending := map[string]map[string]struct{}{}
	for _, ca := range cas {
		if !ca.Spec.RolloutOnCredentialUpdate {
			continue
		}
		ns := ca.Namespace
		if pending[ns] == nil {
			pending[ns] = map[string]struct{}{}
		}
		for _, svc := range ca.Spec.BTP.Services {
			pending[ns][svc.Secret] = struct{}{}
		}
	}

	for ns, secrets := range pending {
		m.restoreSecrets(ns, secrets)
		m.queue.AddAfter(ns, m.rolloutDelay)
		klog.InfoS("startup rollout check: enqueued namespace", "namespace", ns, "secrets", len(secrets))
	}
	return nil
}

// rolls out affected deployments for all CAPApplications in the namespace that have RolloutOnCredentialUpdate enabled.
func (m *rolloutManager) processNamespace(ctx context.Context, namespace string, affectedSecrets map[string]struct{}) error {
	if len(affectedSecrets) == 0 {
		klog.InfoS("no affected secrets exist for this namespace. Skipping rollout..", "namespace", namespace)
		return nil
	}

	cas, err := m.ctrl.crdInformerFactory.Sme().V1alpha1().CAPApplications().Lister().CAPApplications(namespace).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error listing CAPApplications in namespace %s: %w", namespace, err)
	}
	for _, ca := range cas {
		if !ca.Spec.RolloutOnCredentialUpdate {
			continue
		}
		affectedServiceNames := btpServicesForSecrets(ca, affectedSecrets)
		if len(affectedServiceNames) == 0 {
			continue
		}
		if err := m.processAffectedApplication(ctx, ca, affectedServiceNames); err != nil {
			util.LogError(err, "error rolling out application for credential update", "controller", ca, nil, "application", ca.Name)
			return err
		}
	}
	return nil
}

// returns the set of BTP service names in the CA that refer to the provided affected secrets.
func btpServicesForSecrets(ca *v1alpha1.CAPApplication, affectedSecrets map[string]struct{}) map[string]struct{} {
	result := map[string]struct{}{}
	for _, serviceInfo := range ca.Spec.BTP.Services {
		if _, ok := affectedSecrets[serviceInfo.Secret]; ok {
			result[serviceInfo.Name] = struct{}{}
		}
	}
	return result
}

// triggers processing of all relevant CAVs for the CA
func (m *rolloutManager) processAffectedApplication(ctx context.Context, ca *v1alpha1.CAPApplication, affectedServiceNames map[string]struct{}) error {
	relevantCAVs, err := m.ctrl.collectRelevantCAVs(ca)
	if err != nil {
		return fmt.Errorf("error collecting CAVs for %s: %w", ca.Name, err)
	}
	for _, cav := range relevantCAVs {
		if err := m.processAffectedVersion(ctx, ca, cav, affectedServiceNames); err != nil {
			util.LogError(err, "error rolling out CAV for credential update", "processAffectedApplication", cav, nil, "application", ca.Name, "version", cav.Name)
			return err
		}
	}
	return nil
}

// collects all affected deployment workloads and rolls out those that consume at least one of the affected BTP services.
func (m *rolloutManager) processAffectedVersion(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, affectedServiceNames map[string]struct{}) error {
	ownerRef := *metav1.NewControllerRef(cav, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CAPApplicationVersionKind))
	for i := range cav.Spec.Workloads {
		workload := &cav.Spec.Workloads[i]
		if workload.DeploymentDefinition == nil || !workloadConsumesAffectedService(workload, affectedServiceNames) {
			continue
		}
		if err := m.ctrl.rolloutWorkloadDeployment(ctx, ca, cav, workload, ownerRef); err != nil {
			util.LogError(err, "error rolling out workload deployment for credential update", "processAffectedVersion", cav, nil, "workload", workload.Name)
			return err
		}
	}
	return nil
}

// reports whether the workload consumes any service from affectedServiceNames
func workloadConsumesAffectedService(workload *v1alpha1.WorkloadDetails, affectedServiceNames map[string]struct{}) bool {
	for _, svcName := range workload.ConsumedBTPServices {
		if _, ok := affectedServiceNames[svcName]; ok {
			return true
		}
	}
	return false
}

// returns the latest ready CAV plus all ready CAVs currently in use by tenants.
func (c *Controller) collectRelevantCAVs(ca *v1alpha1.CAPApplication) (map[string]*v1alpha1.CAPApplicationVersion, error) {
	relevantCAVs := map[string]*v1alpha1.CAPApplicationVersion{}

	latestCav, err := c.getLatestReadyCAPApplicationVersion(ca, true)
	if err != nil {
		return nil, err
	}
	if latestCav != nil {
		relevantCAVs[latestCav.Name] = latestCav
	}

	if err = c.addTenantCAVs(ca, relevantCAVs); err != nil {
		return nil, err
	}
	return relevantCAVs, nil
}

// appends all ready CAVs referenced by ready tenants of the CA into the provided map.
func (c *Controller) addTenantCAVs(ca *v1alpha1.CAPApplication, relevantCAVs map[string]*v1alpha1.CAPApplicationVersion) error {
	tenants, err := c.getRelevantTenantsForCA(ca)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		if tenant.Status.State != v1alpha1.CAPTenantStateReady || tenant.Status.CurrentCAPApplicationVersionInstance == "" {
			continue
		}
		cavName := tenant.Status.CurrentCAPApplicationVersionInstance
		if _, seen := relevantCAVs[cavName]; seen {
			continue
		}
		cav, err := c.crdInformerFactory.Sme().V1alpha1().CAPApplicationVersions().Lister().CAPApplicationVersions(ca.Namespace).Get(cavName)
		if err != nil {
			util.LogError(err, "error getting CAPApplicationVersion for credential rollout", "controller", ca, nil, "application", ca.Name, "version", cavName)
			continue
		}
		if isCROConditionReady(cav.Status.GenericStatus) {
			relevantCAVs[cav.Name] = cav
		}
	}
	return nil
}

// rotates the VCAP secret used by the affected deployment workload and updates the deployment's envFrom reference to trigger a
// Kubernetes rollout with fresh credentials.
func (c *Controller) rolloutWorkloadDeployment(ctx context.Context, ca *v1alpha1.CAPApplication, cav *v1alpha1.CAPApplicationVersion, workload *v1alpha1.WorkloadDetails, ownerRef metav1.OwnerReference) error {
	deploymentName := getWorkloadName(cav.Name, workload.Name)

	deployment, err := c.kubeClient.AppsV1().Deployments(cav.Namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if k8sErrors.IsNotFound(err) {
		return nil // not yet created, nothing to roll out
	}
	if err != nil {
		return fmt.Errorf("error getting deployment %s for credential rollout: %w", deploymentName, err)
	}
	consumedServiceInfos := getConsumedServiceInfos(getConsumedServiceMap(workload.ConsumedBTPServices), ca.Spec.BTP.Services)
	vcapEnv, err := generateVCAPEnv(cav.Namespace, consumedServiceInfos, c.kubeInformerFactory)
	if err != nil {
		return err
	}

	unchanged, err := c.checkVCAPSecret(ctx, cav.Namespace, deploymentName, ownerRef, vcapEnv)
	if err != nil {
		return err
	}
	if unchanged {
		klog.InfoS("VCAP_SERVICES content unchanged, skipping rollout", "deployment", deploymentName)
		return nil
	}

	newVCAPSecretName, err := c.createSecretFromVCAPEnv(cav.Namespace, ownerRef, deploymentName, vcapEnv, true)
	if err != nil {
		return fmt.Errorf("error creating new VCAP secret for deployment %s: %w", deploymentName, err)
	}

	if err = c.updateDeploymentVCAPRef(ctx, cav.Namespace, deployment, newVCAPSecretName); err != nil {
		return err
	}

	util.LogInfo("Deployment updated for credential rollout", string(Ready), cav,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: cav.Namespace}},
		"deployment", deploymentName, "vcapSecret", newVCAPSecretName)
	return nil
}

// deletes the existing VCAP secret for the deployment so createVCAPSecret will regenerate it with fresh credential data.
func (c *Controller) checkVCAPSecret(ctx context.Context, namespace, deploymentName string, ownerRef metav1.OwnerReference, vcapEnv []byte) (bool, error) {
	validVCAPExists := false
	secretSelector := labels.SelectorFromSet(map[string]string{
		LabelSecretOwnerHash: sha1Sum(namespace, ownerRef.Name, deploymentName),
	})
	existingSecrets, err := c.kubeInformerFactory.Core().V1().Secrets().Lister().Secrets(namespace).List(secretSelector)
	if err != nil {
		return validVCAPExists, fmt.Errorf("error listing VCAP secrets for deployment %s: %w", deploymentName, err)
	}

	for _, s := range existingSecrets {
		if bytes.Equal(s.Data[EnvVCAPServices], vcapEnv) {
			validVCAPExists = true
			continue
		}
		if delErr := c.kubeClient.CoreV1().Secrets(namespace).Delete(ctx, s.Name, metav1.DeleteOptions{}); delErr != nil && !k8sErrors.IsNotFound(delErr) {
			return validVCAPExists, fmt.Errorf("error deleting VCAP secret %s for deployment %s: %w", s.Name, deploymentName, delErr)
		}
	}
	return validVCAPExists, nil
}

// patches the deployment's container envFrom entries to point to the new VCAP secret name, causing Kubernetes to roll out new
// pods with the updated credentials.
func (c *Controller) updateDeploymentVCAPRef(ctx context.Context, namespace string, deployment *appsv1.Deployment, vcapSecretName string) error {
	updated := deployment.DeepCopy()
	newEnvFrom := getEnvFrom(vcapSecretName)
	for j := range updated.Spec.Template.Spec.Containers {
		updated.Spec.Template.Spec.Containers[j].EnvFrom = newEnvFrom
	}
	for j := range updated.Spec.Template.Spec.InitContainers {
		updated.Spec.Template.Spec.InitContainers[j].EnvFrom = newEnvFrom
	}
	if _, err := c.kubeClient.AppsV1().Deployments(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating deployment %s for credential rollout: %w", deployment.Name, err)
	}
	return nil
}
