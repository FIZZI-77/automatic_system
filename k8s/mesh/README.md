# Istio mesh

`policies/` contains the baseline applied by the local HA and production overlays:

- namespace-wide strict mTLS for meshed workloads;
- plaintext exceptions only for the public Gateway and Frontend workload ports;
- bounded connection pools for application clients;
- audit-only detection of unauthenticated backend traffic.

Infrastructure workloads such as Patroni, PgBouncer, Kafka, Redis, MinIO and
observability storage remain outside the mesh. Istio auto-mTLS therefore must
not be replaced with a wildcard `ISTIO_MUTUAL` destination rule.

## Canary test

`scenarios/api-gateway-canary.yaml` is intentionally opt-in. Before applying it,
run stable and canary Gateway deployments behind the same Service and label
their pod templates respectively:

```yaml
app.kubernetes.io/version: stable
```

```yaml
app.kubernetes.io/version: canary
```

Then apply the scenario and verify the 90/10 split, mTLS, errors and latency in
Kiali. Retries are limited to `/livez` and `/readyz`; business requests are not
retried because their idempotency is not guaranteed.

Do not enable enforcing `AuthorizationPolicy` until each application has its
own Kubernetes ServiceAccount. With the shared `default` account, Istio cannot
reliably distinguish Gateway and backend SPIFFE identities.
# Istio ingress

The local mesh exposes the application through the Istio ingress gateway:

- `https://city.localhost` routes to the frontend;
- `https://api.city.localhost` routes to API Gateway;
- browser-to-ingress traffic uses TLS with HTTP/2 negotiated through ALPN;
- ingress-to-API Gateway traffic uses h2c;
- ingress-to-frontend remains HTTP/1.1 because the current vinext server does not expose h2c.

`k8s/scripts/install-mesh.ps1` installs the ingress gateway and creates a two-year
self-signed local certificate. Trust the certificate locally or accept the browser
warning before opening the frontend. To rotate it, run:

```powershell
.\k8s\scripts\setup-ingress.ps1 -RotateCertificate
```
