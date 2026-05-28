from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HarEntry:
    method: str
    url: str
    headers: dict[str, str]
    query_params: dict[str, str]
    post_data_mime: str = ""
    post_data_text: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""


def parse_har(path: str | Path) -> list[HarEntry]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    entries = raw.get("log", {}).get("entries", [])
    parsed: list[HarEntry] = []
    for item in entries:
        req = item.get("request", {})
        resp = item.get("response", {})
        post = req.get("postData", {}) or {}
        content = resp.get("content", {}) or {}
        parsed.append(HarEntry(
            method=str(req.get("method", "GET")).upper(),
            url=req.get("url", ""),
            headers=_headers(req.get("headers", [])),
            query_params={p.get("name", ""): p.get("value", "") for p in req.get("queryString", []) if p.get("name") is not None},
            post_data_mime=post.get("mimeType", ""),
            post_data_text=post.get("text", ""),
            response_status=int(resp.get("status") or 0),
            response_headers=_headers(resp.get("headers", [])),
            response_body=content.get("text", "") or "",
        ))
    return parsed


def _headers(items: Any) -> dict[str, str]:
    if isinstance(items, dict):
        return {str(k): str(v) for k, v in items.items()}
    out = {}
    for item in items or []:
        name = item.get("name")
        if name:
            out[str(name)] = str(item.get("value", ""))
    return out
