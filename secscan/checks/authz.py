from __future__ import annotations

import re
from typing import AsyncIterator, Any
from urllib.parse import urlsplit
from .base import Check, Endpoint, Finding
from .common import more_access, poc
from secscan.utils.http import fingerprint_spa_shell

_ID_NAME_RE = re.compile(r"^(id|.*_id|uuid|ref|resource|account|tenant|object|hash)$", re.I)
_SHORT_HASH_RE = re.compile(r"^[a-f0-9]{6,16}$", re.I)


def _more_permissive(baseline: Any, response: Any) -> bool:
    return more_access(baseline, response)


def _is_spa_shell(response: Any) -> bool:
    return fingerprint_spa_shell(response.headers, response.body_text).looks_like_shell


class AuthzCheck(Check):
    name = "authz"
    description = "Basic authorization probes."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        for param in getattr(endpoint, "mutable_params", []) or []:
            if _resource_identifier_param(param) and _SHORT_HASH_RE.match(str(param.get("sample_value", ""))):
                yield Finding("authz", "low", "medium", "Weak hash-like resource identifier", "A short hash-like value appears in a resource identifier position.", {"sub_technique": "hash_id_weakness", "param": param}, poc(endpoint), "Use non-enumerable identifiers and enforce object-level authorization server-side.")
                return
        sample_segments = urlsplit(endpoint.sample_url).path.strip("/").split("/")
        template_segments = urlsplit(endpoint.url_template).path.strip("/").split("/")
        for template_segment, sample_segment in zip(template_segments, sample_segments):
            if template_segment.lower() in {"{id}", "{uuid}", "{hash}"} and _SHORT_HASH_RE.match(sample_segment):
                yield Finding("authz", "low", "medium", "Weak hash-like resource identifier", "A short hash-like path segment may be enumerable.", {"sub_technique": "hash_id_weakness", "segment": sample_segment}, poc(endpoint), "Use non-enumerable identifiers and enforce object-level authorization server-side.")
                return


def _resource_identifier_param(param: dict) -> bool:
    name = str(param.get("name") or param.get("path") or "")
    if name.lower() in {"email", "password", "q", "query", "search", "username"}:
        return False
    return bool(_ID_NAME_RE.match(name) or name.lower().endswith(("_id", "id")))
