#!/usr/bin/env python3
"""Provision the UMA resource server in the lab Keycloak (idempotent).

This is the scripted equivalent of "configure a UMA resource server" from the
Lecture 9 practice. It creates a confidential client `uma-photo-rs` with
**Authorization Services** enabled - that is what turns a client into a UMA
resource server - and then registers:

  - scopes:     album:view, album:delete
  - resource:   "Photo Album"  (scopes: view, delete)
  - policy:     "alice-can-view"  (user policy: alice)
  - permission: "view album -> alice"  (scope album:view on the album, guarded by
                the alice policy)

Result: alice may `album:view`; nobody may `album:delete`. Enough to show the
whole UMA ticket -> RPT flow, including a denial.

Env (defaults target the course lab):
  KC_BASE       https://keycloak.192.168.50.10.nip.io
  REALM         api-security
  ADMIN_USER    admin
  ADMIN_PASS    admin
  RS_CLIENT_ID  uma-photo-rs
  RS_SECRET     uma-photo-rs-secret-lab-2026
  ALLOWED_USER  alice
  LAB_INGRESS_IP  (optional) resolve the KC host to this IP if the *.nip.io
                  ingress is not reachable from the host - like `curl --resolve`

Run:  python create_uma_client.py
"""
import os
import socket
import sys
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()

KC_BASE = os.environ.get("KC_BASE", "https://keycloak.192.168.50.10.nip.io")
REALM = os.environ.get("REALM", "api-security")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
RS_CLIENT_ID = os.environ.get("RS_CLIENT_ID", "uma-photo-rs")
RS_SECRET = os.environ.get("RS_SECRET", "uma-photo-rs-secret-lab-2026")
ALLOWED_USER = os.environ.get("ALLOWED_USER", "alice")
ADMIN = f"{KC_BASE}/admin/realms/{REALM}"

# Optional lab-connectivity shim (see module docstring).
_ip = os.environ.get("LAB_INGRESS_IP")
if _ip:
    _host = urlparse(KC_BASE).hostname
    _real = socket.getaddrinfo
    socket.getaddrinfo = lambda host, *a, **k: _real(_ip if host == _host else host, *a, **k)

s = requests.Session()
s.verify = False


def token():
    r = s.post(f"{KC_BASE}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS})
    r.raise_for_status()
    return r.json()["access_token"]


def kc(method, path, tok, **kw):
    r = s.request(method, f"{ADMIN}{path}", headers={"Authorization": f"Bearer {tok}"}, **kw)
    if r.status_code >= 400 and r.status_code != 409:
        print(f"   ! {method} {path} -> {r.status_code}: {r.text[:200]}")
    return r


def ensure_client(tok):
    existing = kc("GET", f"/clients?clientId={RS_CLIENT_ID}", tok).json()
    rep = {
        "clientId": RS_CLIENT_ID,
        "name": "UMA Photo Resource Server (Lecture 9)",
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,       # needed to obtain a PAT
        "authorizationServicesEnabled": True,  # makes it a UMA resource server
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "secret": RS_SECRET,
        "protocol": "openid-connect",
    }
    if existing:
        cid = existing[0]["id"]
        kc("PUT", f"/clients/{cid}", tok, json={**existing[0], **rep})
        print(f"[client] updated {RS_CLIENT_ID} ({cid})")
    else:
        kc("POST", "/clients", tok, json=rep)
        cid = kc("GET", f"/clients?clientId={RS_CLIENT_ID}", tok).json()[0]["id"]
        print(f"[client] created {RS_CLIENT_ID} ({cid})")
    return cid


def ensure_scope(tok, cid, name):
    base = f"/clients/{cid}/authz/resource-server/scope"
    for sc in kc("GET", base, tok).json():
        if sc["name"] == name:
            return sc["id"]
    return kc("POST", base, tok, json={"name": name}).json()["id"]


def ensure_resource(tok, cid, name, scope_names):
    base = f"/clients/{cid}/authz/resource-server/resource"
    for res in kc("GET", base, tok).json():
        if res["name"] == name:
            return res["_id"]
    rep = {"name": name, "type": "urn:uma-photo:album",
           "scopes": [{"name": n} for n in scope_names], "ownerManagedAccess": False}
    return kc("POST", base, tok, json=rep).json()["_id"]


def ensure_user_policy(tok, cid, name, user_id):
    base = f"/clients/{cid}/authz/resource-server/policy"
    for p in kc("GET", f"{base}?permission=false", tok).json():
        if p["name"] == name:
            return p["id"]
    rep = {"name": name, "type": "user", "logic": "POSITIVE",
           "decisionStrategy": "UNANIMOUS", "users": [user_id]}
    return kc("POST", f"{base}/user", tok, json=rep).json()["id"]


def ensure_scope_permission(tok, cid, name, resource_id, scope_id, policy_id):
    base = f"/clients/{cid}/authz/resource-server/permission"
    for p in kc("GET", f"{base}?permission=true", tok).json():
        if p["name"] == name:
            return p["id"]
    rep = {"name": name, "type": "scope", "logic": "POSITIVE",
           "decisionStrategy": "UNANIMOUS", "resources": [resource_id],
           "scopes": [scope_id], "policies": [policy_id]}
    return kc("POST", f"{base}/scope", tok, json=rep).json().get("id")


def user_id(tok, username):
    users = kc("GET", f"/users?username={username}&exact=true", tok).json()
    if not users:
        sys.exit(f"user {username} not found in realm {REALM}")
    return users[0]["id"]


def main():
    print("=== UMA resource server setup ===")
    tok = token()
    cid = ensure_client(tok)
    view = ensure_scope(tok, cid, "album:view")
    delete = ensure_scope(tok, cid, "album:delete")
    print(f"[scopes] album:view={view[:8]} album:delete={delete[:8]}")
    album = ensure_resource(tok, cid, "Photo Album", ["album:view", "album:delete"])
    print(f"[resource] Photo Album = {album}")
    policy = ensure_user_policy(tok, cid, "alice-can-view", user_id(tok, ALLOWED_USER))
    print(f"[policy] alice-can-view = {policy[:8]} (user={ALLOWED_USER})")
    perm = ensure_scope_permission(tok, cid, "view album -> alice", album, view, policy)
    print(f"[permission] view album -> alice = {perm and perm[:8]}")
    print("\nDone. album:view is granted to alice only; album:delete to nobody.")


if __name__ == "__main__":
    main()
