#!/usr/bin/env python3
"""UMA 2.0 reference client - drives the flow against the deployed uma-rs.

Walks the UMA 2.0 ceremony from the lecture:

  1. GET the resource with no RPT              -> 401 + WWW-Authenticate (ticket, as_uri)
  2. exchange the ticket for an RPT at the AS  (grant_type=uma-ticket, RqP's token)
  3. GET the resource again with the RPT       -> 200

Then two denials: alice asking for a scope she lacks (album:delete), and bob
asking for album:view (not in the policy).

Env (defaults target the course lab):
  KC_BASE, REALM, RS_URL, RQP_CLIENT, ALICE/ALICE_PASS, BOB/BOB_PASS
  LAB_INGRESS_IP  (optional) resolve the *.nip.io hosts to this IP off-lab

Run:  python uma_client.py            # add LAB_INGRESS_IP=<vm-ip> off-lab
"""
import base64
import json
import os
import re
import socket
import sys
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()

KC_BASE = os.environ.get("KC_BASE", "https://keycloak.192.168.50.10.nip.io")
REALM = os.environ.get("REALM", "api-security")
RS_URL = os.environ.get("RS_URL", "https://uma-rs.192.168.50.10.nip.io")
TOKEN_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
UMA_GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket"

RQP_CLIENT = os.environ.get("RQP_CLIENT", "spa-token-demo")  # public, direct access
ALICE = os.environ.get("ALICE", "alice"); ALICE_PASS = os.environ.get("ALICE_PASS", "alice")
BOB = os.environ.get("BOB", "bob"); BOB_PASS = os.environ.get("BOB_PASS", "bob")

# Optional off-lab connectivity shim - resolve the KC + RS hosts to one VM IP.
_ip = os.environ.get("LAB_INGRESS_IP")
if _ip:
    _hosts = {urlparse(KC_BASE).hostname, urlparse(RS_URL).hostname}
    _real = socket.getaddrinfo
    socket.getaddrinfo = lambda host, *a, **k: _real(_ip if host in _hosts else host, *a, **k)

s = requests.Session(); s.verify = False


def decode_jwt(t):
    p = t.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def user_token(user, password):
    r = s.post(TOKEN_URL, data={"grant_type": "password", "client_id": RQP_CLIENT,
               "username": user, "password": password, "scope": "openid"})
    r.raise_for_status()
    return r.json()["access_token"]


def attempt(label, method, path, user, password, scope_hint):
    print(f"\n[{label}]")
    r = s.request(method, f"{RS_URL}{path}")
    print(f"   1. {method} {path} (no RPT) -> {r.status_code}")
    if r.status_code != 401:
        print("      unexpected:", r.text[:200]); return
    wa = r.headers.get("WWW-Authenticate", "")
    as_uri = re.search(r'as_uri="([^"]+)"', wa).group(1)
    ticket = re.search(r'ticket="([^"]+)"', wa).group(1)
    print(f"      WWW-Authenticate: as_uri={as_uri} ticket={ticket[:18]}...")

    utok = user_token(user, password)
    r = s.post(f"{as_uri}/protocol/openid-connect/token",
               headers={"Authorization": f"Bearer {utok}"},
               data={"grant_type": UMA_GRANT, "ticket": ticket})
    if r.status_code != 200:
        b = r.json()
        print(f"   2. RPT request -> {r.status_code}  {b.get('error')} ({b.get('error_description')})")
        print(f"      => {user} is DENIED {scope_hint}. No RPT, so the RS stays closed.")
        return
    rpt = r.json()["access_token"]
    perms = decode_jwt(rpt).get("authorization", {}).get("permissions", [])
    print(f"   2. RPT request -> 200  permissions={[(p.get('rsname'), p.get('scopes')) for p in perms]}")

    r = s.request(method, f"{RS_URL}{path}", headers={"Authorization": f"Bearer {rpt}"})
    print(f"   3. {method} {path} (with RPT) -> {r.status_code}  {r.json().get('message')}")


def main():
    print("=" * 55)
    print("UMA 2.0 client - permission ticket -> RPT -> access")
    print("=" * 55)
    if s.get(f"{RS_URL}/api/health").status_code != 200:
        sys.exit(f"resource server not reachable at {RS_URL}")
    attempt("alice views the album (allowed)", "GET", "/api/album", ALICE, ALICE_PASS, "album:view")
    attempt("alice deletes the album (no permission)", "DELETE", "/api/album", ALICE, ALICE_PASS, "album:delete")
    attempt("bob views the album (not in policy)", "GET", "/api/album", BOB, BOB_PASS, "album:view")
    print("\ndone")


if __name__ == "__main__":
    main()
