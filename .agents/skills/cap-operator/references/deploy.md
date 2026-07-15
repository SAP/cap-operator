# Deploy a New CAP Application

Three-step sequence: Domain → CAPApplication → CAPApplicationVersion.

## Step 1 — Domain resource

**Namespace-scoped (single app):**

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: Domain
metadata:
  name: cap-app-01-primary
  namespace: cap-app-01
spec:
  domain: my.cluster.shoot.url.k8s.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple      # Simple | Mutual | OptionalMutual
  dnsMode: Wildcard    # None | Wildcard | Subdomain | Custom
```

**Cluster-scoped (shared across apps):**

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: ClusterDomain
metadata:
  name: common-external-domain
spec:
  domain: my.example.com
  ingressSelector:
    app: istio-ingressgateway
    istio: ingressgateway
  tlsMode: Simple
  dnsMode: Subdomain
```

## Step 2 — CAPApplication

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplication
metadata:
  name: cap-app-01
  namespace: cap-app-01
spec:
  btpAppName: cap-app-01          # matches xsappname registered with SaaS Registry
  providerSubaccountId: <provider-subaccount-guid>
  btp:
    services:
      - class: xsuaa
        name: app-uaa
        secret: cap-app-01-uaa-bind-cf
      - class: saas-registry
        name: app-saas-registry
        secret: cap-app-01-saas-bind-cf
      - class: service-manager
        name: app-service-manager
        secret: cap-app-01-svc-man-bind-cf
      # add destination, html5-apps-repo, portal, etc. as needed
      # optionally control subscription dependency inclusion:
      # subscriptionDependency: Auto | Always | Never
  domainRefs:
    - kind: Domain
      name: cap-app-01-primary
    - kind: ClusterDomain
      name: common-external-domain
```

## Step 3 — CAPApplicationVersion

```yaml
apiVersion: sme.sap.com/v1alpha1
kind: CAPApplicationVersion
metadata:
  name: cav-cap-app-01-1
  namespace: cap-app-01
spec:
  capApplicationInstance: cap-app-01
  version: "1.0.0"               # semantic version, must be unique per CAPApplication
  registrySecrets:
    - regcred
  workloads:
    - name: cap-backend
      consumedBTPServices:
        - app-uaa
        - app-service-manager
        - app-saas-registry
      deploymentDefinition:
        type: CAP                 # CAP | Router | Additional | Service
        image: <registry>/srv/server:1.0.0
        env:
          - name: CDS_ENV
            value: production
        ports:
          - name: app-port
            port: 4004
            routerDestinationName: cap-server-url  # exposes as named Approuter destination
    - name: app-router
      consumedBTPServices:
        - app-uaa
        - app-saas-registry
      deploymentDefinition:
        type: Router
        image: <registry>/approuter:1.0.0
        env:
          - name: PORT
            value: "5000"
          - name: TENANT_HOST_PATTERN
            value: "^(.*).my.cluster.shoot.url.k8s.example.com"
    - name: service-content
      consumedBTPServices:
        - app-uaa
        - app-html5-repo-host
      jobDefinition:
        type: Content             # runs once when CAPApplicationVersion is created
        image: <registry>/content:1.0.0
        backoffLimit: 1
    - name: tenant-operation      # REQUIRED for multi-tenant apps
      consumedBTPServices:
        - app-uaa
        - app-service-manager
        - app-saas-registry
      jobDefinition:
        type: TenantOperation     # uses cds-mtxs APIs for HDI deployment
        image: <registry>/srv/server:1.0.0
        backoffLimit: 2
        ttlSecondsAfterFinished: 300
  # tenantOperations is optional if no CustomTenantOperation workloads are used
```

## What the controller creates automatically

- `Deployment` + `Service` for each deployment workload (with `VCAP_SERVICES` env var injected)
- `Job` for each Content workload
- `Certificate` (Gardener or cert-manager.io)
- Istio `Gateway` for the application domains

`CAPApplicationVersion` reaches `Ready` once all workloads are running and content jobs complete.

## Services-only applications (no multi-tenancy)

Omit `TenantOperation` workloads from `CAPApplicationVersion` and omit `providerSubaccountId` from `CAPApplication`. No `CAPTenant` resources are created.

> Note: the application mode (services-only vs. multi-tenant) cannot be changed after initial deployment.

## Tenant lifecycle (automated)

- **Subscribe:** Consumer subaccount subscribes → subscription server creates `CAPTenant` → controller creates `CAPTenantOperation` (type: `provisioning`) → jobs run → `VirtualService` created → `CAPTenant` reaches `Ready`.
- **Unsubscribe:** Subscription server marks `CAPTenant` for deletion → controller creates `CAPTenantOperation` (type: `deprovisioning`) → jobs run → `CAPTenant` deleted.

The `getDependencies` endpoint is exposed automatically at:
```
GET /dependencies/{providerSubaccountId}/{appName}/
```
