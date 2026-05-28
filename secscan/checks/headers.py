from __future__ import annotations

from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import poc
from .payloads.headers import INSECURE_CSP_TOKENS, REQUIRED_HEADERS


class HeadersCheck(Check):
    name = "headers"
    description = "Security header checks."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        resp = await replay.baseline(endpoint)
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        for key, display in REQUIRED_HEADERS.items():
            if key not in headers:
                yield Finding("headers", "medium" if key == "content-security-policy" else "low", "high", f"Missing {display}", f"Response is missing {display}.", {"sub_technique": f"missing_{key}", "header": display, "status": resp.status_code}, poc(endpoint), f"Add a defensive {display} header appropriate for this application.")
        csp = headers.get("content-security-policy", "")
        for token in INSECURE_CSP_TOKENS:
            if token in csp:
                yield Finding("headers", "medium", "medium", "Weak Content-Security-Policy", f"CSP contains {token}.", {"sub_technique": "weak_csp", "token": token, "csp": csp}, poc(endpoint), "Remove unsafe CSP tokens and use nonce/hash based script policies.")
