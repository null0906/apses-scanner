from __future__ import annotations

import json
from typing import Any
from secscan.utils.http import request_to_curl


def injectable_params(endpoint: Any) -> list[dict[str, Any]]:
    return [p for p in getattr(endpoint, "mutable_params", []) or [] if p.get("classification") == "mutable"]


def poc(endpoint: Any, param: dict[str, Any] | None = None, payload: str | None = None) -> str:
    body = getattr(endpoint, "request_body", None)
    raw = None
    if isinstance(body, dict):
        raw = body.get("raw") or (json.dumps(body.get("json")) if "json" in body else None)
    return request_to_curl({"method": getattr(endpoint, "method", "GET"), "url": getattr(endpoint, "sample_url", ""), "headers": getattr(endpoint, "request_headers", {}), "body": raw})


def body_has_token(text: str) -> bool:
    lowered = (text or "").lower()
    return any(key in lowered for key in ('"token"', '"access_token"', '"jwt"', '"session"', '"role":"admin"', '"isadmin":true'))


def more_access(baseline: Any, response: Any) -> bool:
    if baseline.status_code in {401, 403} and 200 <= response.status_code < 300 and response.body_size > 0:
        return True
    if body_has_token(response.body_text) and not body_has_token(baseline.body_text):
        return True
    return False
