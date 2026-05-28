from __future__ import annotations
from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import injectable_params, poc
from .payloads.redirect import PARAM_NAMES, REDIRECT_PAYLOADS


class RedirectCheck(Check):
    name = "redirect"
    description = "Open redirect checks on captured redirect-like parameters."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        for param in injectable_params(endpoint):
            if (param.get("name") or "").lower() not in {p.lower() for p in PARAM_NAMES}:
                continue
            for payload in REDIRECT_PAYLOADS:
                resp = await replay.inject(endpoint, param, payload)
                loc = resp.headers.get("location") or resp.headers.get("Location") or ""
                if loc.startswith(payload):
                    yield Finding("redirect", "medium", "medium", "Open redirect", "Redirect parameter accepted an external URL.", {"sub_technique": "external_redirect", "param": param, "payload": payload, "location": loc}, poc(endpoint), "Allow-list redirect destinations and use relative redirect identifiers.")
                    return
