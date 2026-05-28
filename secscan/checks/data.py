from __future__ import annotations

import math
import re
from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import poc
from .payloads.data import ERROR_LEAK_PATTERNS, SECRET_PATTERNS


class DataExposureCheck(Check):
    name = "data"
    description = "Sensitive data exposure in responses."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        resp = await replay.baseline(endpoint)
        text = resp.body_text or ""
        jwt_pattern = SECRET_PATTERNS["jwt"]
        for name, pattern in SECRET_PATTERNS.items():
            match = re.search(pattern, text)
            if match:
                if name == "generic_secret" and re.search(jwt_pattern, text[match.start():match.start() + 2000]):
                    continue
                if name == "email" and '"authentication"' in text.lower() and '"token"' in text.lower():
                    continue
                sev = "medium" if name in {"jwt", "generic_secret", "aws_access_key"} else "low"
                yield Finding("data", sev, "medium", f"Sensitive data exposure: {name}", f"Response body contains data matching {name}.", {"sub_technique": name, "match_excerpt": _excerpt(text, match.start())}, poc(endpoint), "Remove secrets and sensitive identifiers from responses unless strictly required.")
        lowered = text.lower()
        leak = next((p for p in ERROR_LEAK_PATTERNS if p in lowered), None)
        if leak:
            yield Finding("data", "medium", "medium", "Verbose error or stack leakage", "Response contains framework or stack trace details.", {"sub_technique": "verbose_error", "signature": leak}, poc(endpoint), "Return generic errors to clients and log stack traces server-side only.")
        token = _high_entropy(text)
        if token:
            yield Finding("data", "medium", "low", "High-entropy value exposed", "Response contains a high-entropy token-like value.", {"sub_technique": "high_entropy", "sample": token[:80]}, poc(endpoint), "Review whether token-like values need to be exposed to the client.")


def _excerpt(text: str, pos: int) -> str:
    return text[max(0, pos-80):pos+160]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(ch)/len(value))*math.log2(value.count(ch)/len(value)) for ch in set(value))


def _high_entropy(text: str) -> str | None:
    for token in re.findall(r"[A-Za-z0-9_./+=-]{32,}", text or ""):
        if _looks_like_url_fragment(token):
            continue
        if token.startswith("eyJ") and token.count(".") >= 2:
            continue
        if _entropy(token) > 4.2:
            return token
    return None


def _looks_like_url_fragment(value: str) -> bool:
    lowered = value.lower()
    return (
        "://" in lowered
        or lowered.startswith("/")
        or ".com/" in lowered
        or ".io/" in lowered
        or ".org/" in lowered
    )
