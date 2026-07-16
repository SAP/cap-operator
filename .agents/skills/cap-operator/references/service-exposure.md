# Service Exposures (Tenant-Agnostic)

`serviceExposures` in `CAPApplicationVersion` exposes deployment workloads at fixed subdomains, independent of tenant routing. Works with any deployment type: `CAP`, `Router`, `Additional`, or `Service`.

## Configuration

```yaml
spec:
  workloads:
    - name: cap-backend
      consumedBTPServices:
        - cap-uaa
        - cap-saas-reg
      deploymentDefinition:
        type: CAP
        image: <registry>/server:1.0.0
        ports:
          - name: app-port
            port: 4004
          - name: api-v2
            port: 8001
          - name: api
            port: 8000
    - name: app
      consumedBTPServices:
        - cap-uaa
      deploymentDefinition:
        type: Service
        image: <registry>/app:1.0.0
        ports:
          - name: app-port
            port: 5000
  serviceExposures:
    - subDomain: service
      routes:
        - workloadName: cap-backend
          port: 4004
    - subDomain: api
      routes:
        - workloadName: cap-backend
          port: 8001
          path: /api/v2           # more specific path first
        - workloadName: cap-backend
          port: 8000
          path: /api
    - subDomain: app
      routes:
        - workloadName: app
          port: 5000
```

For a domain `my.example.com` this produces:

| URL | Target |
|---|---|
| `service.my.example.com` | `cap-backend:4004` |
| `api.my.example.com/api/v2` | `cap-backend:8001` |
| `api.my.example.com/api` | `cap-backend:8000` |
| `app.my.example.com` | `app:5000` |

**Important:** Order routes most-specific-first within a `subDomain` to avoid routing conflicts (e.g. `/api/v2` before `/api`).

See `website/content/en/docs/usage/service-exposure.md` | [Service exposure](https://sap.github.io/cap-operator/docs/usage/service-exposure/).
