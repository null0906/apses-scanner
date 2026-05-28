from __future__ import annotations

import os
import re
from typing import AsyncIterator
from .base import Check, Endpoint, Finding
from .common import injectable_params, poc
from .payloads.ssrf import METADATA_URLS, URL_PARAM_NAMES

_INSTANCE_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b", re.I)
_METADATA_MARKERS = ["ami-id", "instance-id", "security-credentials", "computeMetadata/v1"]


class SSRFCheck(Check):
    name = "ssrf"
    description = "SSRF checks requiring callback or returned metadata evidence."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        for param in injectable_params(endpoint):
            if (param.get("name") or "").lower() not in URL_PARAM_NAMES:
                continue
            for payload in METADATA_URLS:
                resp = await replay.inject(endpoint, param, payload)
                body = resp.body_text
                if _metadata_evidence(body):
                    yield Finding("ssrf", "high", "medium", "Cloud metadata returned through SSRF probe", "Metadata content was returned in the HTTP response.", {"sub_technique": "cloud_metadata", "param": param, "payload": payload, "excerpt": body[:500]}, poc(endpoint), "Block server-side requests to link-local metadata and validate outbound destinations.")
                    return
        if not os.environ.get("INTERACTSH_URL"):
            return


def _metadata_evidence(body: str) -> bool:
    lowered = (body or "").lower()
    return bool(_INSTANCE_ID_RE.search(body or "") or any(marker.lower() in lowered for marker in _METADATA_MARKERS))
