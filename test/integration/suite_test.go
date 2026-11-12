//go:build integration

/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

// Package integration contains envtest-based integration ("e2e-like") tests for the
// CAP Operator. Unlike the unit tests in internal/controller (which use fake
// clientsets), these tests run the real controller against a real kube-apiserver +
// etcd started by controller-runtime's envtest, with the CAP Operator CRDs and the
// required external CRDs (Istio, cert-manager) installed.
//
// The suite is gated behind the `integration` build tag so that `go test ./...` is
// unaffected. Run it with:
//
//	make -C hack test-integration
//
// or manually:
//
//	KUBEBUILDER_ASSETS=$(setup-envtest use -p path) \
//	    go test -tags integration ./test/integration/... -count=1
//
// NOTE: envtest binaries (kube-apiserver, etcd) are published for linux/amd64 and
// darwin only. On Windows run the suite in CI or WSL.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	certManager "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	gardenerCert "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	dns "github.com/gardener/external-dns-management/pkg/client/dns/clientset/versioned"
	promop "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	"github.com/sap/cap-operator/internal/controller"
	"github.com/sap/cap-operator/pkg/client/clientset/versioned"
	istio "istio.io/client-go/pkg/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// testEnv holds the shared state for the integration suite, initialised once in
// TestMain and consumed by individual tests via the package-level `env` variable.
type testEnv struct {
	cfg           *rest.Config
	kubeClient    kubernetes.Interface
	copClient     versioned.Interface
	istioClient   istio.Interface
	controllerCtx context.Context
}

// env is the shared suite environment. It is only valid while TestMain is running
// m.Run(), i.e. inside the test functions.
var env *testEnv

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

// run performs setup, executes the tests and performs teardown. It is a separate
// function so that deferred cleanup runs before os.Exit.
func run(m *testing.M) (code int) {
	// Select the dependency managers that minimise the external CRD surface:
	//   - cert-manager.io for certificates (small CRD, vendored under testdata)
	//   - kubernetes-native DNS, which needs no extra CRD / informer at all
	// These are read by the controller via os.Getenv at startup. The env var names
	// and values mirror the (unexported) constants in internal/controller/utils.go.
	os.Setenv("CERT_MANAGER", "cert-manager.io")
	os.Setenv("DNS_MANAGER", "kubernetes")

	testEnvironment := &envtest.Environment{
		CRDDirectoryPaths: []string{
			// CAP Operator CRDs (source of truth in the repo root)
			filepath.Join("..", "..", "crds"),
			// Minimal external CRDs required by the controller's informers/reconcilers
			filepath.Join("testdata", "crd", "external"),
		},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnvironment.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start test environment: %v\n", err)
		return 1
	}
	defer func() {
		if stopErr := testEnvironment.Stop(); stopErr != nil {
			fmt.Fprintf(os.Stderr, "could not stop test environment: %v\n", stopErr)
		}
	}()

	// Give the controller generous client-side rate limits so reconciliation is not
	// throttled during tests.
	cfg.QPS = 100
	cfg.Burst = 200

	clients, err := buildClients(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build clients: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := controller.NewController(
		clients.kube, clients.cop, clients.istio,
		clients.gardenerCert, clients.certManager, clients.gardenerDNS, clients.prom,
	)
	go c.Start(ctx)

	// Allow informers to start and perform their initial cache sync before tests run.
	// Tests additionally poll with timeouts, so this only avoids a noisy warm-up.
	time.Sleep(2 * time.Second)

	env = &testEnv{
		cfg:           cfg,
		kubeClient:    clients.kube,
		copClient:     clients.cop,
		istioClient:   clients.istio,
		controllerCtx: ctx,
	}

	return m.Run()
}

type suiteClients struct {
	kube         kubernetes.Interface
	cop          versioned.Interface
	istio        istio.Interface
	gardenerCert gardenerCert.Interface
	certManager  certManager.Interface
	gardenerDNS  dns.Interface
	prom         promop.Interface
}

// buildClients constructs the seven clients that controller.NewController requires,
// mirroring cmd/controller/main.go. The Gardener clients are created but unused given
// the cert-manager/kubernetes-DNS configuration selected in run().
func buildClients(cfg *rest.Config) (*suiteClients, error) {
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	copClient, err := versioned.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cap-operator client: %w", err)
	}
	istioClient, err := istio.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("istio client: %w", err)
	}
	gardenerCertClient, err := gardenerCert.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("gardener certificate client: %w", err)
	}
	certManagerClient, err := certManager.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cert-manager client: %w", err)
	}
	dnsClient, err := dns.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("gardener dns client: %w", err)
	}
	promClient, err := promop.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("prometheus-operator client: %w", err)
	}

	return &suiteClients{
		kube:         kubeClient,
		cop:          copClient,
		istio:        istioClient,
		gardenerCert: gardenerCertClient,
		certManager:  certManagerClient,
		gardenerDNS:  dnsClient,
		prom:         promClient,
	}, nil
}
