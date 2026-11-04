#!/usr/bin/env python3
"""Local RBAC practice target for OpenAPI-RBAC-Tester. Standard library only.

    python3 demo/rbac_target.py            # http://127.0.0.1:8099
    python3 demo/rbac_target.py 9000       # other port

Identities (Bearer tokens):
    anon      no Authorization header
    user      Bearer user-token
    admin     Bearer admin-token

Also accepts the same tokens as a cookie: session=user-token / session=admin-token,
or as X-API-Key, so each auth style in the extension can be exercised.

Endpoints are tiered so every divergence class shows up in the grid:
    GET    /health                    200 for everyone
    GET    /openapi.json              200 for everyone (the spec)
    GET    /users/me                  401 anon, 200 user/admin
    GET    /users                     401 anon, 403 user, 200 admin
    GET    /users/{id}                401 anon, 200 own id for user, 200 any for admin, else 403
    GET    /admin/audit-log           401 anon, 404 user (hidden), 200 admin   <- the "404 means forbidden" case
    GET    /admin/config              401 anon, 403 user, 200 admin
    POST   /users                     401 anon, 403 user, 201 admin
    DELETE /users/{id}                401 anon, 403 user, 204 admin           <- destructive
    POST   /auth/logout               200 for any token                         <- destructive
    GET    /reports?from=..&to=..     401 anon, 200 user/admin (query params in the spec)
    GET    /broken/idor/{id}          200 for ANY token, any id                 <- the bug to find
                                     (needs user + user2 configured: peers)
    GET    /broken/support-view       401 anon, 200 user, 403 admin             <- inverted check, shows red
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099

TOKENS = {
    "user-token": {"name": "user", "id": 7, "role": "user"},
    "user2-token": {"name": "user2", "id": 9, "role": "user"},
    "admin-token": {"name": "admin", "id": 1, "role": "admin"},
}

USERS = {
    1: {"id": 1, "name": "admin", "email": "admin@example.test"},
    7: {"id": 7, "name": "user", "email": "user@example.test"},
    9: {"id": 9, "name": "user2", "email": "user2@example.test"},
}


def spec(base_url):
    def op(summary, tag, security=True, params=None, responses=None, body=None):
        o = {"summary": summary, "tags": [tag], "responses": responses or {"200": {"description": "OK"}}}
        if security:
            o["security"] = [{"bearerAuth": []}, {"cookieAuth": []}, {"apiKeyAuth": []}]
        if params:
            o["parameters"] = params
        if body:
            o["requestBody"] = body
        return o

    id_param = [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}]
    json_body = {"required": True, "content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}, "email": {"type": "string"}}}}}}

    return {
        "openapi": "3.0.3",
        "info": {"title": "RBAC practice target", "version": "1.0",
                 "description": "Tiered endpoints for exercising OpenAPI-RBAC-Tester."},
        "servers": [{"url": base_url}],
        "components": {"securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }},
        "paths": {
            "/health": {"get": op("Liveness", "public", security=False)},
            "/users/me": {"get": op("Current user", "users")},
            "/users": {
                "get": op("List users (admin)", "users"),
                "post": op("Create user (admin)", "users", body=json_body,
                           responses={"201": {"description": "Created"}}),
            },
            "/users/{id}": {
                "get": op("Get user", "users", params=id_param),
                "delete": op("Delete user (admin)", "users", params=id_param,
                             responses={"204": {"description": "Deleted"}}),
            },
            "/admin/audit-log": {"get": op("Audit log (admin)", "admin")},
            "/admin/config": {"get": op("Runtime config (admin)", "admin")},
            "/auth/logout": {"post": op("Invalidate session", "auth")},
            "/reports": {"get": op("Reports in a date range", "reports", params=[
                {"name": "from", "in": "query", "required": True, "schema": {"type": "string", "format": "date"}},
                {"name": "to", "in": "query", "required": True, "schema": {"type": "string", "format": "date"}},
            ])},
            "/broken/idor/{id}": {"get": op("User profile export (has an IDOR)", "users", params=id_param)},
            "/broken/support-view": {"get": op("Support dashboard (role check is inverted)", "admin")},
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "rbac-target/1.0"

    # ---- helpers -----------------------------------------------------------
    def identity(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return TOKENS.get(auth[7:].strip())
        key = self.headers.get("X-API-Key")
        if key:
            return TOKENS.get(key.strip())
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session":
                return TOKENS.get(v.strip())
        return None

    def send(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def deny(self, who):
        # 401 when there is no identity at all, 403 when there is one without rights.
        if who is None:
            self.send(401, {"error": "authentication required"})
        else:
            self.send(403, {"error": "forbidden", "as": who["name"]})

    def path_id(self, prefix):
        rest = self.path_only[len(prefix):]
        try:
            return int(rest)
        except ValueError:
            return None

    # ---- routing -----------------------------------------------------------
    def do_GET(self):
        self.path_only = urlparse(self.path).path
        who = self.identity()
        p = self.path_only

        if p == "/health":
            return self.send(200, {"ok": True})
        if p == "/openapi.json":
            host = self.headers.get("Host", f"127.0.0.1:{PORT}")
            return self.send(200, spec(f"http://{host}"))
        if p == "/users/me":
            return self.send(200, who) if who else self.deny(who)
        if p == "/users":
            return self.send(200, list(USERS.values())) if who and who["role"] == "admin" else self.deny(who)
        if p.startswith("/users/"):
            uid = self.path_id("/users/")
            if who is None:
                return self.deny(who)
            if uid is None or uid not in USERS:
                return self.send(404, {"error": "no such user"})
            if who["role"] == "admin" or who["id"] == uid:
                return self.send(200, USERS[uid])
            return self.deny(who)
        if p == "/admin/audit-log":
            if who is None:
                return self.deny(who)
            if who["role"] != "admin":
                return self.send(404, {"error": "not found"})  # hides existence from non-admins
            return self.send(200, [{"ts": "2026-11-04T06:00:00Z", "event": "login", "user": "admin"}])
        if p == "/admin/config":
            return self.send(200, {"debug": False, "tier": "prod"}) if who and who["role"] == "admin" else self.deny(who)
        if p == "/reports":
            if who is None:
                return self.deny(who)
            q = parse_qs(urlparse(self.path).query)
            return self.send(200, {"from": q.get("from", [None])[0], "to": q.get("to", [None])[0], "rows": 3})
        if p.startswith("/broken/idor/"):
            uid = self.path_id("/broken/idor/")
            if who is None:
                return self.deny(who)
            # Bug on purpose: never checks that uid belongs to the caller.
            return self.send(200, USERS.get(uid, {"id": uid, "name": "ghost"}))
        if p == "/broken/support-view":
            if who is None:
                return self.deny(who)
            # Bug on purpose: the check is `role == "user"` where it should be `!= "user"`.
            if who["role"] == "user":
                return self.send(200, {"tickets": 3})
            return self.deny(who)
        self.send(404, {"error": "not found"})

    def do_POST(self):
        self.path_only = urlparse(self.path).path
        who = self.identity()
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path_only == "/auth/logout":
            return self.send(200, {"logged_out": who["name"] if who else None})
        if self.path_only == "/users":
            return self.send(201, {"id": 10, "created": True}) if who and who["role"] == "admin" else self.deny(who)
        self.send(404, {"error": "not found"})

    def do_DELETE(self):
        self.path_only = urlparse(self.path).path
        who = self.identity()
        if self.path_only.startswith("/users/"):
            return self.send(204) if who and who["role"] == "admin" else self.deny(who)
        self.send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        who = self.identity()
        sys.stderr.write("%s  %-5s  %s\n" % (who["name"] if who else "anon", self.command, fmt % args))


if __name__ == "__main__":
    print(f"RBAC target on http://127.0.0.1:{PORT}   spec: http://127.0.0.1:{PORT}/openapi.json")
    print("tokens: user-token, user2-token, admin-token (Bearer, X-API-Key, or session= cookie)")
    print("user and user2 are peers: the IDOR row only lights up when both are configured")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
