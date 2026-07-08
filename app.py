"""UMA 2.0 resource server for the API Security course - Lecture 9.

A protected "Photo Album" API. It never evaluates policy itself - it asks the
Keycloak Authorization Server (the AS). On a request without a sufficient RPT it:

  1. uses its own PAT (client_credentials) to ask the AS for a **permission ticket**
     for the resource + scope being requested (UMA Protection API), then
  2. answers **401** with `WWW-Authenticate: UMA realm=.., as_uri=.., ticket=..`.

On a request that carries an RPT it verifies the RPT (Keycloak signature + issuer)
and checks that its `authorization.permissions` covers this resource and scope.

  GET    /api/album   requires scope album:view
  DELETE /api/album   requires scope album:delete
  GET    /api/health  liveness

It is deliberately dependency-light and readable - teaching material, not a
framework showcase. Config is env-overridable; defaults target the course lab.
"""
import json
import os
import time

import jwt  # PyJWT
import requests
from flask import Flask, jsonify, request

# --- config (env-overridable; defaults target the course lab) ----------------
ISSUER = os.environ.get(
    "KEYCLOAK_ISSUER_URI",
    "https://keycloak.192.168.50.10.nip.io/realms/api-security",
)
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
PROTECTION = f"{ISSUER}/authz/protection"          # UMA Protection API base
RESOURCE_SET_URL = f"{PROTECTION}/resource_set"
PERMISSION_URL = f"{PROTECTION}/permission"

# The resource server authenticates as this confidential client (Authorization
# Services enabled) to obtain its PAT and call the Protection API.
RS_CLIENT_ID = os.environ.get("RS_CLIENT_ID", "uma-photo-rs")
RS_CLIENT_SECRET = os.environ.get("RS_CLIENT_SECRET", "uma-photo-rs-secret-lab-2026")
RESOURCE_NAME = os.environ.get("RESOURCE_NAME", "Photo Album")

# The lab uses a self-signed internal CA. Point OAUTH_CA_BUNDLE at a CA file to verify.
VERIFY = os.environ.get("OAUTH_CA_BUNDLE", False)
if not VERIFY:
    requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
_s = requests.Session()
_s.verify = VERIFY
_state = {"pat": None, "pat_exp": 0, "rid": None, "jwks": {}, "jwks_ts": 0.0}


# --- Keycloak / UMA plumbing -------------------------------------------------
def _decode_no_verify(token):
    import base64
    p = token.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def pat():
    """Protection API Token - the RS's own client_credentials access token."""
    if not _state["pat"] or time.time() > _state["pat_exp"] - 30:
        r = _s.post(TOKEN_URL, data={"grant_type": "client_credentials",
                    "client_id": RS_CLIENT_ID, "client_secret": RS_CLIENT_SECRET})
        r.raise_for_status()
        _state["pat"] = r.json()["access_token"]
        _state["pat_exp"] = _decode_no_verify(_state["pat"])["exp"]
    return _state["pat"]


def resource_id():
    """Look up (once) the id of our registered resource via the Protection API."""
    if not _state["rid"]:
        r = _s.get(RESOURCE_SET_URL, params={"name": RESOURCE_NAME},
                   headers={"Authorization": f"Bearer {pat()}"})
        r.raise_for_status()
        ids = r.json()
        if not ids:
            raise RuntimeError(f"resource '{RESOURCE_NAME}' is not registered - run setup")
        _state["rid"] = ids[0]
    return _state["rid"]


def create_ticket(scope):
    """Protection API: mint a permission ticket for this resource + scope."""
    r = _s.post(PERMISSION_URL, headers={"Authorization": f"Bearer {pat()}"},
                json=[{"resource_id": resource_id(), "resource_scopes": [scope]}])
    r.raise_for_status()
    return r.json()["ticket"]


def _signing_key(kid):
    if not _state["jwks"] or time.time() - _state["jwks_ts"] > 300:
        keys = _s.get(JWKS_URI).json().get("keys", [])
        _state["jwks"] = {k["kid"]: k for k in keys if k.get("kid")}
        _state["jwks_ts"] = time.time()
    k = _state["jwks"].get(kid)
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) if k else None


def rpt_permissions(token):
    """Verify the RPT and return its granted permissions, or None if invalid."""
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        claims = jwt.decode(token, _signing_key(kid), algorithms=["RS256", "ES256"],
                            issuer=ISSUER, options={"verify_aud": False})
    except Exception as e:  # noqa: BLE001
        app.logger.info("RPT invalid: %s", e)
        return None
    return claims.get("authorization", {}).get("permissions", [])


def has_scope(perms, scope):
    return any(scope in (p.get("scopes") or []) and p.get("rsname") == RESOURCE_NAME
               for p in perms)


def enforce(scope):
    """Return None if allowed, else a 401 Flask response carrying a fresh ticket."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        perms = rpt_permissions(auth[7:])
        if perms is not None and has_scope(perms, scope):
            return None  # allowed
    ticket = create_ticket(scope)
    resp = jsonify(error="unauthorized",
                   detail=f"need scope {scope} on '{RESOURCE_NAME}' - trade the ticket for an RPT")
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = f'UMA realm="{ISSUER.rsplit("/", 1)[-1]}", as_uri="{ISSUER}", ticket="{ticket}"'
    return resp


# --- routes ------------------------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify(status="UP", resource=RESOURCE_NAME)


@app.get("/api/album")
def view_album():
    denied = enforce("album:view")
    if denied:
        return denied
    return jsonify(album=RESOURCE_NAME, photos=["beach.jpg", "sunset.jpg"],
                   message="album:view granted - you hold an RPT for this scope")


@app.delete("/api/album")
def delete_album():
    denied = enforce("album:delete")
    if denied:
        return denied
    return jsonify(deleted=True, message="album:delete granted")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
