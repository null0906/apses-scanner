from __future__ import annotations
from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import injectable_params, poc
from .payloads.xss import REFLECTED


class XSSCheck(Check):
    name = "xss"
    description = "Reflected XSS checks for captured API inputs."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        for param in injectable_params(endpoint):
            for payload in REFLECTED:
                resp = await replay.inject(endpoint, param, payload)
                ctype = (resp.headers.get("content-type") or "").lower()
                if payload in resp.body_text and "html" in ctype:
                    yield Finding("xss", "high", "medium", "Reflected XSS payload reflected in HTML", "Injected payload was reflected in an HTML response.", {"sub_technique": "reflected", "param": param, "payload": payload}, poc(endpoint), "Contextually encode output and sanitize HTML sinks.")
                    return
