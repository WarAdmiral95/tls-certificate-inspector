# TLS Certificate Toolkit (v0.2.0)

Browser-based TLS diagnostics, X.509 certificate inspection, PEM bundle validation, and Java JKS generation.

## Features

- Inspect remote public HTTPS endpoints (port 443)
- Paste or upload PEM/DER certificates and inspect each certificate in a multi-cert chain
- Inspect subject, issuer, dates, SAN, public key, key usage, extensions, PEM, fingerprints
- Validate **ordered** chains against an explicitly supplied root trust anchor (leaf → intermediate(s) → root). Shows separate signature/structure and trust statuses. **Not a full RFC 5280 path validator**; it does not validate hostname, revocation, certificate policies, name constraints, or public trust for uploaded files.
- Create `truststore.jks` from CA-only bundle (one alias per CA)
- Create `keystore.jks` from leaf certificate, matching PEM private key, and ordered CA chain; root generally not necessary. Supports encrypted PEM keys.

## Run

```bash
docker build -t tls-certificate-inspector:0.2.0 .
docker run --rm -p 127.0.0.1:8080:8080 tls-certificate-inspector:0.2.0
```

Open <http://localhost:8080>.

## Helm

```bash
helm upgrade --install tls-inspector ./chart -n devops-tools --create-namespace \
  --set image.repository=YOUR_REGISTRY/tls-certificate-inspector \
  --set image.tag=0.2.0
kubectl port-forward -n devops-tools svc/tls-inspector 8080:80
```

## KIND (local Kubernetes)

Prerequisites: [Docker](https://docs.docker.com/get-docker/), [kind](https://kind.sigs.k8s.io/docs/user/quick-start/), `kubectl`, and `helm`.

```bash
# 1. Create a cluster (skip if you already have one)
kind create cluster --name tls-inspector

# 2. Build the image locally and load it into the KIND nodes (no registry needed)
docker build -t tls-certificate-inspector:0.2.0 .
kind load docker-image tls-certificate-inspector:0.2.0 --name tls-inspector

# 3. Install the chart using the local image
helm upgrade --install tls-inspector ./chart -n devops-tools --create-namespace \
  --set image.repository=tls-certificate-inspector \
  --set image.tag=0.2.0 \
  --set image.pullPolicy=IfNotPresent \
  --set service.type=ClusterIP

# 4. Wait for the pod and open the UI
kubectl rollout status deployment/tls-inspector -n devops-tools
kubectl port-forward -n devops-tools svc/tls-inspector 8080:80
```

Open <http://localhost:8080>.

Notes:

- Always set `image.tag` explicitly. The default in `values.yaml` may not match the image you built.
- Use `service.type=ClusterIP` on KIND. The chart default is `LoadBalancer`, which stays `<pending>` on KIND because there is no cloud load balancer.
- If you use a non-default cluster name, pass the same name to `--name` in `kind load docker-image`. Check with `kind get clusters`.
- After rebuilding the image with the same tag, reload it with `kind load docker-image ...` and run `kubectl rollout restart deployment/tls-inspector -n devops-tools`.
- If the pod shows `ErrImagePull` or `ImagePullBackOff`, the image was not loaded into the cluster. Re-run step 2 and confirm with `docker exec -it tls-inspector-control-plane crictl images | grep tls-certificate-inspector`.
- The "Inspect website" tab needs outbound internet access from the pod. This works on a default KIND cluster if your host has connectivity.

Clean up:

```bash
helm uninstall tls-inspector -n devops-tools
kind delete cluster --name tls-inspector
```

## Security

**Private keys and JKS passwords are sent to the backend** to generate the keystore. Use a trusted deployment over HTTPS with access controls; never expose it anonymously on the internet. The application does not intentionally store private keys or passwords or log request bodies. The conversion process uses a memory-backed `/tmp` volume in Kubernetes; Docker local use relies on container temporary storage. Do not enable request-body logging, tracing, or proxy body capture. Keytool reads passwords from environment variables rather than process arguments. Generated JKS files are returned as downloads and temporary files are deleted. Use a dedicated isolated workload, non-root runtime, resource limits, network policies, and TLS ingress. For high-security production keys, prefer generating the keystore locally instead of uploading keys to any service.

## Validation limits

- Certificates must be in leaf → intermediate(s) → root order for chain validation.
- Trust is established only when an explicit trusted root bundle is provided. A self-signed root embedded in the input is **not automatically trusted**.
- No revocation (CRL/OCSP), name constraints, certificate policies, or hostname checks for uploaded certificates.
- `truststore.jks` accepts only certificates with CA BasicConstraints; `keystore.jks` requires first certificate to match private key.
- PEM/DER certificates supported for inspection. Private keys must be PEM. Input size limit 512 KiB per certificate bundle/key.
- JKS password must be at least 6 characters.

## Verify generated stores

```bash
keytool -list -v -keystore truststore.jks -storetype JKS
keytool -list -v -keystore keystore.jks -storetype JKS
```
