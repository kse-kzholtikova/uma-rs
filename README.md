# uma-rs

A **UMA 2.0 resource server** (RFC-flavored teaching code) for the API Security
course, Lecture 9. It protects a "Photo Album" API and delegates every
authorization decision to the Keycloak Authorization Server.

Deployed in the lab at **https://uma-rs.192.168.50.10.nip.io** (GitOps via
`kse-labs-deployment` -> `applications/uma-rs`).

## The flow it implements

```
client GET /api/album (no RPT)
  -> RS asks the AS for a permission ticket (Protection API, using its PAT)
  -> RS 401 + WWW-Authenticate: UMA realm=.., as_uri=.., ticket=..
client POST /token grant_type=uma-ticket + ticket (as the requesting party)
  -> AS evaluates policy -> RPT
client GET /api/album with the RPT
  -> RS verifies the RPT signature + authorization.permissions -> 200
```

## Endpoints

| Method | Path | Requires scope |
|--------|------|----------------|
| GET | `/api/album` | `album:view` |
| DELETE | `/api/album` | `album:delete` |
| GET | `/api/health` | - |

## Configuration (env)

| Var | Default |
|-----|---------|
| `KEYCLOAK_ISSUER_URI` | `https://keycloak.192.168.50.10.nip.io/realms/api-security` |
| `RS_CLIENT_ID` | `uma-photo-rs` |
| `RS_CLIENT_SECRET` | `uma-photo-rs-secret-lab-2026` |
| `RESOURCE_NAME` | `Photo Album` |
| `OAUTH_CA_BUNDLE` | unset (TLS verify off - lab uses a self-signed CA) |

## Keycloak side

The RS authenticates as the confidential client **`uma-photo-rs`** (Authorization
Services enabled) to obtain its **PAT** and call the Protection API. Provision the
client + resource + scopes + policy + permission with:

```bash
python setup/create_uma_client.py        # add LAB_INGRESS_IP=<vm-ip> off-lab
```

That grants `album:view` to `alice` only, and `album:delete` to nobody - enough to
demonstrate a grant and two denials.

## Drive it

```bash
pip install requests
python demo/uma_client.py                 # add LAB_INGRESS_IP=<vm-ip> off-lab
```

## CI / deploy

`.github/workflows/ci-main.yml` builds the image to `ghcr.io/kse-bd8338bbe006/uma-rs`
and (with the org `DEPLOYMENT_PAT`) bumps the tag in `kse-labs-deployment`
(`applications/uma-rs/deployment.yaml`), which ArgoCD then rolls out.
