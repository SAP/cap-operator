## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.tag | string | `""` | Default image tag (can be overwritten on component level) |
| image.pullPolicy | string | `""` | Default image pull policy (can be overwritten on component level) |
| imagePullSecrets | list | `[]` | Default image pull secrets (can be overwritten on component level) |
| podSecurityContext | object | `{}` | Default pod security content (can be overwritten on component level) |
| nodeSelector | object | `{}` | Default node selector (can be overwritten on component level) |
| affinity | object | `{}` | Default affinity settings (can be overwritten on component level) |
| tolerations | list | `[]` | Default tolerations (can be overwritten on component level) |
| priorityClassName | string | `""` | Default priority class (can be overwritten on component level) |
| topologySpreadConstraints | list | `[]` | Default topology spread constraints (can be overwritten on component level) |
| podLabels | object | `{}` | Additional pod labels for all components |
| podAnnotations | object | `{}` | Additional pod annotations for all components |
| controller.replicas | int | `1` | Replicas |
| controller.image.repository | string | `"ghcr.io/sap/cap-operator/controller"` | Image repository |
| controller.image.tag | string | `""` | Image tag |
| controller.image.pullPolicy | string | `""` | Image pull policy |
| controller.imagePullSecrets | list | `[]` | Image pull secrets |
| controller.podLabels | object | `{}` | Additional labels for controller pods |
| controller.podAnnotations | object | `{}` | Additional annotations for controller pods |
| controller.podSecurityContext | object | `{}` | Pod security content |
| controller.nodeSelector | object | `{}` | Node selector |
| controller.affinity | object | `{}` | Affinity settings |
| controller.tolerations | list | `[]` | Tolerations |
| controller.priorityClassName | string | `""` | Priority class |
| controller.topologySpreadConstraints | list | `[]` | Topology spread constraints |
| controller.securityContext | object | `{}` | Security context |
| controller.resources.limits.memory | string | `"500Mi"` | Memory limit |
| controller.resources.limits.cpu | float | `0.2` | CPU limit |
| controller.resources.requests.memory | string | `"50Mi"` | Memory request |
| controller.resources.requests.cpu | float | `0.02` | CPU request |
| controller.volumes | list | `[]` | Optionally specify list of additional volumes for the controller pod(s) |
| controller.volumeMounts | list | `[]` | Optionally specify list of additional volumeMounts for the controller container(s) |
| controller.dnsTarget | string | `""` | The dns target mentioned on the public ingress gateway service used in the cluster |
| controller.versionMonitoring.prometheusAddress | string | `""` | The URL of the Prometheus server from which metrics related to managed application versions can be queried  |
| controller.versionMonitoring.metricsEvaluationInterval | string | `"1h"` | The duration (example 2h) after which versions are evaluated for deletion; based on specified workload metrics |
| controller.versionMonitoring.promClientAcquireRetryDelay | string | `"1h"` | The duration (example 10m) to wait before retrying to acquire Prometheus client and verify connection, after a failed attempt |
| subscriptionServer.replicas | int | `1` | Replicas |
| subscriptionServer.image.repository | string | `"ghcr.io/sap/cap-operator/server"` | Image repository |
| subscriptionServer.image.tag | string | `""` | Image tag |
| subscriptionServer.image.pullPolicy | string | `""` | Image pull policy |
| subscriptionServer.imagePullSecrets | list | `[]` | Image pull secrets |
| subscriptionServer.podLabels | object | `{}` | Additional labels for subscription server pods |
| subscriptionServer.podAnnotations | object | `{}` | Additional annotations for subscription server pods |
| subscriptionServer.podSecurityContext | object | `{}` | Pod security content |
| subscriptionServer.nodeSelector | object | `{}` | Node selector |
| subscriptionServer.affinity | object | `{}` | Affinity settings |
| subscriptionServer.tolerations | list | `[]` | Tolerations |
| subscriptionServer.priorityClassName | string | `""` | Priority class |
| subscriptionServer.topologySpreadConstraints | list | `[]` | Topology spread constraints |
| subscriptionServer.securityContext | object | `{}` | Security context |
| subscriptionServer.resources.limits.memory | string | `"200Mi"` | Memory limit |
| subscriptionServer.resources.limits.cpu | float | `0.1` | CPU limit |
| subscriptionServer.resources.requests.memory | string | `"20Mi"` | Memory request |
| subscriptionServer.resources.requests.cpu | float | `0.01` | CPU request |
| subscriptionServer.volumes | list | `[]` | Optionally specify list of additional volumes for the server pod(s) |
| subscriptionServer.volumeMounts | list | `[]` | Optionally specify list of additional volumeMounts for the server container(s) |
| subscriptionServer.port | int | `4000` | Service port |
| subscriptionServer.istioSystemNamespace | string | `"istio-system"` | The namespace in the cluster where istio system components are installed |
| subscriptionServer.ingressGatewayLabels | object | `{"app":"istio-ingressgateway","istio":"ingressgateway"}` | Labels used to identify the istio ingress-gateway component |
| subscriptionServer.dnsTarget | string | `"public-ingress.clusters.cs.services.sap"` | The dns target mentioned on the public ingress gateway service used in the cluster |
| subscriptionServer.domain | string | `"cap-operator.clusters.cs.services.sap"` | The domain under which the cap operator subscription server would be available |
| webhook.sidecar | bool | `false` | Side car to mount admission review |
| webhook.replicas | int | `1` | Replicas |
| webhook.image.repository | string | `"ghcr.io/sap/cap-operator/web-hooks"` | Image repository |
| webhook.image.tag | string | `""` | Image tag |
| webhook.image.pullPolicy | string | `""` | Image pull policy |
| webhook.imagePullSecrets | list | `[]` | Image pull secrets |
| webhook.podLabels | object | `{}` | Additional labels for validating webhook pods |
| webhook.podAnnotations | object | `{}` | Additional annotations for validating webhook pods |
| webhook.podSecurityContext | object | `{}` | Pod security content |
| webhook.nodeSelector | object | `{}` | Node selector |
| webhook.affinity | object | `{}` | Affinity settings |
| webhook.tolerations | list | `[]` | Tolerations |
| webhook.priorityClassName | string | `""` | Priority class |
| webhook.topologySpreadConstraints | list | `[]` | Topology spread constraints |
| webhook.securityContext | object | `{}` | Security context |
| webhook.resources.limits.memory | string | `"200Mi"` | Memory limit |
| webhook.resources.limits.cpu | float | `0.1` | CPU limit |
| webhook.resources.requests.memory | string | `"20Mi"` | Memory request |
| webhook.resources.requests.cpu | float | `0.01` | CPU request |
| webhook.service | object | `{"port":443,"targetPort":1443,"type":"ClusterIP"}` | Service port |
| webhook.service.type | string | `"ClusterIP"` | Service type |
| webhook.service.port | int | `443` | Service port |
| webhook.service.targetPort | int | `1443` | Target port |
